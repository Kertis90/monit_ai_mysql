// Доказательство исполнением: настоящий showAsk из web/app.js прогоняется
// на заглушке DOM, и видно, какую разметку он делает.
//
// Нужно потому, что «в коде есть кнопки» и «кнопки появятся» — разные
// утверждения. Первое проверяется поиском по файлу, второе — только
// запуском. Когда кнопок не оказывалось у человека на экране, спорить
// можно было бесконечно; запуск прекращает спор.
//
// Печатает разметку и код возврата: 0 — кнопки есть во всех случаях.
const fs = require('fs');

const src = fs.readFileSync('web/app.js', 'utf8');

// Вырезаем showAsk и esc как есть, без изменений
function cut(name) {
  const start = src.indexOf('function ' + name + '(');
  if (start < 0) throw new Error('не найдена функция ' + name);
  let depth = 0, i = src.indexOf('{', start);
  const from = i;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') { depth--; if (!depth) break; }
  }
  return src.slice(start, i + 1);
}

const stub = `
  const made = [];
  function el(tag) {
    return {
      tag, id: '', className: '', innerHTML: '', disabled: false,
      children: [],
      appendChild(c) { this.children.push(c); },
      addEventListener() {},
      querySelectorAll() { return []; },
      querySelector() { return null; },
      remove() {},
      focus() {},
    };
  }
  const messages = el('div');
  const input = el('input');
  const document = { createElement: el };
  const state = { asking: false, streamingEl: null, wsReady: true, threadId: 't' };
  function $(id) { return id === 'messages' ? messages : (id === 'input' ? input : null); }
  function scrollToBottom() {}
  function addToFeed(e) { messages.appendChild(e); }
  function closeAsk() {}
  ${cut('esc')}
  ${cut('showAsk')}
`;

function render(msg) {
  const box = new Function(stub + `
    showAsk(${JSON.stringify(msg)});
    return { html: messages.children[0] && messages.children[0].innerHTML,
             inputEnabled: !input.disabled, asking: state.asking };
  `)();
  return box;
}

console.log('── Как отдаёт сервер (два варианта) ──────────────────────');
let r = render({ question: 'Агент сделал 4 запроса и пока не закончил сбор. Продолжаем?',
                 options: [{ value: 'yes', label: 'Продолжить сбор' },
                           { value: 'no', label: 'Ответить по тому, что есть' }],
                 timeout: 120 });
console.log(r.html);
console.log('кнопок:', (r.html.match(/<button/g) || []).length,
            '| поле ввода открыто:', r.inputEnabled, '| режим ответа:', r.asking);

console.log('');
console.log('── Если вариантов не пришло вовсе ────────────────────────');
r = render({ question: 'Продолжаем?', timeout: 120 });
console.log(r.html);
console.log('кнопок:', (r.html.match(/<button/g) || []).length);

console.log('');
console.log('── Если options пришло пустым списком ────────────────────');
r = render({ question: 'Продолжаем?', options: [], timeout: 0 });
console.log('кнопок:', (r.html.match(/<button/g) || []).length);

// Итог для вызывающего: во всех трёх случаях кнопок должно быть две
const cases = [
  { question: 'Продолжаем?',
    options: [{ value: 'yes', label: 'Продолжить сбор' },
              { value: 'no', label: 'Ответить по тому, что есть' }],
    timeout: 120 },
  { question: 'Продолжаем?', timeout: 120 },
  { question: 'Продолжаем?', options: [], timeout: 0 },
];
const bad = cases.filter(c => (render(c).html.match(/<button/g) || []).length !== 2);
if (bad.length) {
  console.error('НЕТ КНОПОК в случаях: ' + bad.length);
  process.exit(1);
}
console.log('');
console.log('Во всех случаях кнопок по две.');
