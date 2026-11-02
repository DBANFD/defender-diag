const tools = document.querySelector('.library-tools');
if (tools) {
  tools.hidden = false;
  const input = document.querySelector('#search');
  const buttons = [...document.querySelectorAll('[data-filter]')];
  const notes = [...document.querySelectorAll('.note-item')];
  let topic = 'All';
  function update() {
    const query = input.value.trim().toLowerCase();
    let count = 0;
    for (const note of notes) {
      note.hidden = !((topic === 'All' || note.dataset.topic === topic) && note.textContent.toLowerCase().includes(query));
      if (!note.hidden) count++;
    }
    document.querySelector('#result-count').textContent = `${count} ${count === 1 ? 'note' : 'notes'}${topic === 'All' ? ' across all topics' : ' in ' + topic.toLowerCase()}`;
    document.querySelector('.empty').hidden = count !== 0;
  }
  for (const button of buttons) button.addEventListener('click', () => {
    topic = button.dataset.filter;
    for (const item of buttons) item.setAttribute('aria-pressed', String(item === button));
    update();
  });
  input.addEventListener('input', update);
}
