document.addEventListener('DOMContentLoaded', () => {
  const yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  const cta = document.getElementById('cta');
  if (cta) {
    cta.addEventListener('click', () => {
      alert('Hello from Deploy Site!');
    });
  }
});
