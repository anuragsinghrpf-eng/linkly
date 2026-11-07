import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateEarning, deviceCategory, nextStepPosition, publicStepState, safeAlias, validateAdDestination, validateDestination, validatePassword } from '../src/domain.mjs';

test('destination validation allows only safe HTTP and HTTPS URLs', () => {
  assert.equal(validateDestination('https://example.com/path'), 'https://example.com/path');
  assert.equal(validateDestination('javascript:alert(1)'), null);
  assert.equal(validateDestination('data:text/html,x'), null);
  assert.equal(validateDestination('https://user:pass@example.com'), null);
  assert.equal(validateAdDestination('https://partner.example/?event={event_id}'), 'https://partner.example/?event={event_id}');
  assert.equal(validateAdDestination('file:///tmp/x'), null);
});

test('aliases and passwords meet basic format rules', () => {
  assert.equal(safeAlias('summer_26'), 'summer_26');
  assert.equal(safeAlias('x'), undefined);
  assert.equal(safeAlias(''), null);
  assert.equal(validatePassword('StrongPass123'), true);
  assert.equal(validatePassword('short'), false);
});

test('earning calculation uses integer paise and rounds down', () => {
  assert.equal(calculateEarning(2000, 1000), 2000);
  assert.equal(calculateEarning(2000, 1), 2);
  assert.equal(calculateEarning(1500, 1), 1);
  assert.throws(() => calculateEarning(-1, 1));
});

test('unlock progression exposes only the next enabled step', () => {
  const steps = [1,2,3].map(position => ({position,enabled:1,title:`Step ${position}`,label:'Continue',instruction:'',policy:'clickthrough'}));
  assert.equal(nextStepPosition(steps, []), 1);
  assert.equal(nextStepPosition(steps, [1]), 2);
  assert.equal(nextStepPosition(steps, [1,2,3]), null);
  const state = publicStepState(steps, [1], 2);
  assert.equal(state.progress, 33);
  assert.deepEqual(state.steps.map(s => s.status), ['completed','current','locked']);
});

test('coarse device classification identifies bot traffic without storing identifiers', () => {
  assert.equal(deviceCategory('Googlebot/2.1'), 'bot');
  assert.equal(deviceCategory('Mozilla/5.0 (iPhone; CPU iPhone OS)'), 'mobile');
  assert.equal(deviceCategory('Mozilla/5.0 (X11; Linux x86_64)'), 'desktop');
});
