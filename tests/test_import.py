"""F08 executable fixtures; shared by SQLite and migrated PostgreSQL runs."""
import json
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi import HTTPException
from sqlalchemy import select, func
from app.models import Claim, Subject, EventLedger, SubjectBinding
from app.service import canonical
from app.security import sha256
from test_acceptance import env, headers, history


def record(**changes):
    return dict(tenant_id='tenant-a', source_record_id='offer-1', source_person_ref='synthetic-001',
        authenticated_account_id='candidate-a', source_version=1,
        source_updated_at='2026-01-01T00:00:00Z', event_type='offer_accepted',
        role_ref='synthetic-engineer', start_date='2026-11-01', offer_status='accepted',
        effective_from='2026-01-01T00:00:00Z', **changes)


def file(records=None, **changes):
    records = records if records is not None else [record()]
    payload = b''.join(canonical(r) + b'\n' for r in records)
    header = dict(schema_version='1', source_system_id='ATS', tenant_id='tenant-a',
        snapshot_id='snapshot-1', generated_at=datetime.now(timezone.utc).isoformat(),
        record_count=len(records), content_hash=sha256(payload))
    header.update(changes)
    return canonical(header) + b'\n' + payload


def upload(client, raw, **identity):
    return client.post('/imports/ATS', content=raw,
        headers={**headers(roles='data_administrator', **identity), 'Content-Type':'application/x-ndjson'})


def counts(app):
    with app.state.sessions() as db:
        return [db.scalar(select(func.count()).select_from(m)) for m in (Subject, Claim, EventLedger)]


def freshness(client, tenant='tenant-a'):
    return client.get('/imports/ATS/freshness', headers=headers(tenant, roles='data_administrator')).json()


def test_valid_reimport_across_files_and_evidence(env):
    client, app = env
    assert freshness(client)['state'] == 'missing'
    raw = file()
    first = upload(client, raw).json()
    o = first['outcomes'][0]
    assert o['outcome'] == 'accepted' and counts(app) == [1,3,3]
    sid = o['f01']['subject_id']
    duplicate = upload(client, raw).json()
    assert duplicate['duplicate_file'] and duplicate['outcomes'] == first['outcomes']
    assert upload(client, file(snapshot_id='another')) .json()['outcomes'][0]['outcome'] == 'duplicate'
    assert counts(app) == [1,3,3]
    with app.state.sessions() as db:
        assert app.state.service.verify_ledger(db, sid)
        for claim in db.scalars(select(Claim)):
            ev = client.get(f'/subjects/{sid}/evidence/{claim.evidence_id}',
                params={'purpose':'audit_reconstruction'}, headers=headers(roles='auditor'))
            assert ev.status_code == 200 and sha256(ev.content) == claim.evidence_hash
            assert json.loads(ev.content) == json.loads(canonical(record()))
    assert freshness(client)['state'] == 'fresh'
    assert freshness(client, 'tenant-b')['state'] == 'missing'


@pytest.mark.parametrize('header_change', [dict(tenant_id='tenant-b'), dict(source_system_id='HR'),
    dict(schema_version='2'), dict(content_hash='0'*64), dict(record_count=2),
    dict(generated_at='2099-01-01T00:00:00Z')])
def test_file_gate_no_partial_state(env, header_change):
    client, app = env
    assert upload(client, file(**header_change)).status_code == 422
    assert counts(app) == [0,0,0] and freshness(client)['state'] == 'missing'


@pytest.mark.parametrize('change,reason', [({'tenant_id':'tenant-b'},'WRONG_TENANT'),
    ({'source_version':0},'INVALID_RECORD'), ({'source_version':True},'INVALID_RECORD'),
    ({'work_location':'excluded'},'INVALID_RECORD'), ({'start_date':'invalid'},'INVALID_RECORD'),
    ({'source_updated_at':'no-zone'},'INVALID_RECORD'),
    ({'event_type':'offer_updated'},'UNBOUND_SUBJECT')])
def test_quarantine_and_hold_no_payload_or_canonical_state(env, change, reason):
    client, app = env
    r = record(); r.update(change)
    response = upload(client, file([r]))
    assert response.status_code == 200
    assert response.json()['outcomes'][0]['reason_code'] == reason
    assert 'synthetic-engineer' not in response.text and '2026-11-01' not in response.text
    assert counts(app) == [0,0,0] and freshness(client)['state'] == 'missing'


def test_mixed_file_binding_and_offer_identity_checks(env):
    client, app = env
    bad = record(); bad['tenant_id'] = 'tenant-b'
    response = upload(client, file([bad, record()])).json()
    assert [o['outcome'] for o in response['outcomes']] == ['quarantined','accepted']
    altered = record(); altered.update(authenticated_account_id='another-account', event_type='offer_updated', source_version=2)
    assert upload(client,file([altered],snapshot_id='binding')).json()['outcomes'][0]['reason_code'] == 'SUBJECT_BINDING_MISMATCH'
    altered.update(source_person_ref='another-person',event_type='offer_accepted')
    assert upload(client,file([altered],snapshot_id='offer')).json()['outcomes'][0]['reason_code'] == 'SOURCE_RECORD_BINDING_MISMATCH'
    assert counts(app) == [1,3,3]


def test_changed_late_and_same_version_conflict(env):
    client, app = env
    first = upload(client,file()).json()['outcomes'][0]['f01']
    sid = first['subject_id']
    r = record(); r.update(source_version=3,start_date='2026-11-08',event_type='offer_updated')
    assert upload(client,file([r],snapshot_id='new')).json()['outcomes'][0]['outcome'] == 'accepted'
    r.update(source_version=2,start_date='2026-11-04')
    assert upload(client,file([r],snapshot_id='late')).json()['outcomes'][0]['outcome'] == 'historical'
    assert history(client,sid,system_at='2099-01-01T00:00:00Z').json()['predicates']['start_date']['value'] == '2026-11-08'
    r.update(source_version=3,start_date='2026-11-15')
    assert upload(client,file([r],snapshot_id='conflict')).json()['outcomes'][0]['outcome'] == 'contested'
    p = history(client,sid,system_at='2099-01-01T00:00:00Z').json()['predicates']['start_date']
    assert p['conflict_state'] == 'unresolved' and len(p['claims']) == 2
    with app.state.sessions() as db:
        assert app.state.service.verify_ledger(db,sid)


def test_record_atomicity_and_crash_after_f01_commit(env, monkeypatch):
    client, app = env
    original = app.state.service._mutate
    def fail_second(db, identity, sid, body, correlation, commit=True):
        if body.predicate == 'offered_role':
            raise HTTPException(422,'INJECTED_FAILURE')
        return original(db,identity,sid,body,correlation,commit)
    monkeypatch.setattr(app.state.service,'_mutate',fail_second)
    assert upload(client,file()).json()['outcomes'][0]['outcome'] == 'quarantined'
    assert counts(app) == [0,0,0]
    monkeypatch.setattr(app.state.service,'_mutate',original)
    original_offer = app.state.service.import_offer
    def crash(*args):
        original_offer(*args)
        raise RuntimeError('crash after canonical commit')
    monkeypatch.setattr(app.state.service,'import_offer',crash)
    raw = file(snapshot_id='crash')
    with pytest.raises(RuntimeError):
        upload(client,raw)
    assert counts(app) == [1,3,3]
    monkeypatch.setattr(app.state.service,'import_offer',original_offer)
    resumed = upload(client,raw).json()
    assert resumed['complete'] and resumed['outcomes'][0]['outcome'] == 'duplicate'
    assert counts(app) == [1,3,3]


def test_freshness_stale_duplicate_does_not_refresh(env):
    client, _ = env
    old = (datetime.now(timezone.utc)-timedelta(days=8)).isoformat()
    raw = file(generated_at=old)
    assert upload(client,raw).status_code == 200
    assert freshness(client)['state'] == 'stale'
    assert upload(client,raw).json()['duplicate_file']
    assert freshness(client)['state'] == 'stale'
    assert freshness(client)['task_completion'] == 'unknown'


def test_concurrent_same_file(env):
    client, app = env
    raw = file()
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _:upload(client,raw),range(2)))
    assert all(r.status_code == 200 for r in responses)
    assert sum(r.json()['duplicate_file'] for r in responses) == 1
    assert counts(app) == [1,3,3]


@pytest.mark.parametrize('rights', ['restricted','erased'])
def test_restricted_erased_import_cannot_restore(env, rights):
    client, app = env
    sid = upload(client,file()).json()['outcomes'][0]['f01']['subject_id']
    with app.state.sessions() as db:
        subject = db.get(Subject,sid)
        if rights == 'restricted': subject.restricted=True
        else: subject.wrapped_key=subject.key_reference=None
        db.commit()
    r=record();r.update(source_version=2,event_type='offer_updated')
    result=upload(client,file([r],snapshot_id='rights')).json()
    assert result['outcomes'][0]['outcome'] == 'quarantined'
    assert counts(app) == [1,3,3]


def test_role_type_size_and_structure(env):
    client, app=env
    assert client.post('/imports/ATS',content=file(),headers=headers()).status_code == 403
    assert client.post('/imports/ATS',content=file(),headers=headers(roles='data_administrator')).status_code == 415
    assert upload(client,b'x'*262145).status_code == 413
    assert upload(client,b'{}\nnot-json\n').status_code == 422
    assert counts(app) == [0,0,0]


def test_restart_reuses_completed_run(env):
    from app.main import create_app
    from fastapi.testclient import TestClient
    client, app=env
    raw=file()
    first=upload(client,raw).json()
    restarted=create_app(app.state.engine.url.render_as_string(hide_password=False),
                         str(app.state.service.evidence.root))
    with TestClient(restarted) as fresh:
        result=upload(fresh,raw).json()
        assert result['duplicate_file'] and result['outcomes'] == first['outcomes']
        assert freshness(fresh)['state'] == 'fresh'
    assert counts(app) == [1,3,3]
