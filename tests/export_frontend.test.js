const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function loadExportScript(overrides = {}) {
  const templatePath = path.join(__dirname, '..', 'app', 'templates', 'export.html');
  const template = fs.readFileSync(templatePath, 'utf8');
  const match = template.match(/{% block extra_js %}\s*<script>([\s\S]*?)<\/script>\s*{% endblock %}/);
  assert.ok(match, 'export.html inline script should be present');

  const events = [];
  const timers = [];
  const buttons = [{ disabled: false }, { disabled: false }, { disabled: false }];
  const checkedInput = { checked: true, value: '1' };
  const elements = {
    recentImportDropdownLabel: { textContent: '' },
    recentImportEmpty: { style: {}, textContent: '' },
    recentImportDropdown: { style: {}, classList: { toggle() {} } },
    recentImportHint: { style: {} },
    recentImportDropdownMenu: { innerHTML: '' }
  };

  const document = {
    addEventListener() {},
    body: {
      appendChild() {
        events.push('append');
      },
      removeChild() {
        events.push('remove');
      }
    },
    createElement(tagName) {
      assert.equal(tagName, 'a');
      return {
        href: '',
        download: '',
        click() {
          events.push('click');
        }
      };
    },
    getElementById(id) {
      return elements[id] || null;
    },
    querySelectorAll(selector) {
      if (selector === '.export-button') {
        return buttons;
      }
      if (selector === '#recentImportDropdownMenu input:checked') {
        return checkedInput.checked ? [checkedInput] : [];
      }
      if (selector === '#recentImportDropdownMenu input') {
        return [checkedInput];
      }
      return [];
    }
  };

  const window = {
    URL: {
      createObjectURL() {
        events.push('create');
        return 'blob:test-download';
      },
      revokeObjectURL() {
        events.push('revoke');
      }
    },
    setTimeout(callback, delay) {
      timers.push({ callback, delay });
      return timers.length;
    }
  };

  const context = vm.createContext({
    API_BASE: '/api',
    Blob: class Blob {},
    console,
    document,
    fetch: async () => {
      throw new Error('fetch should not be called in this test');
    },
    setTimeout: window.setTimeout,
    showMessage() {},
    window,
    ...overrides,
    __test: { buttons, checkedInput, elements, events, timers }
  });

  vm.runInContext(match[1], context);
  vm.runInContext('recentImports = [{ import_id: 1, filename: "sample.log" }];', context);
  return context;
}

test('triggerDownload keeps the blob URL alive until the browser has handled the click', () => {
  const context = loadExportScript();

  vm.runInContext('triggerDownload({}, "sample.csv")', context);

  assert.deepEqual(context.__test.events, ['create', 'append', 'click', 'remove']);
  assert.equal(context.__test.timers.length, 1);

  context.__test.timers[0].callback();
  assert.deepEqual(context.__test.events, ['create', 'append', 'click', 'remove', 'revoke']);
});

test('exportSelected restores export buttons if an unexpected error escapes', async () => {
  let messageCalls = 0;
  const context = loadExportScript({
    showMessage() {
      messageCalls += 1;
      if (messageCalls === 1) {
        throw new Error('toast failed');
      }
    }
  });

  await assert.rejects(
    vm.runInContext('exportSelected("csv")', context),
    /toast failed/
  );

  assert.deepEqual(
    context.__test.buttons.map(button => button.disabled),
    [false, false, false]
  );
});
