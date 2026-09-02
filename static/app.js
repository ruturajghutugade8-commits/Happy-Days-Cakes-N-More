document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.querySelector('.nav-toggle');
  const nav = document.querySelector('.navlinks');
  if (toggle && nav) {
    toggle.addEventListener('click', () => {
      const open = nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(open));
    });
  }

  const orderType = document.getElementById('order-type');
  const addressField = document.getElementById('address-field');
  if (orderType && addressField) {
    const syncAddress = () => {
      const delivery = orderType.value === 'delivery';
      addressField.classList.toggle('hidden', !delivery);
      const textarea = addressField.querySelector('textarea');
      if (textarea) textarea.required = delivery;
    };
    orderType.addEventListener('change', syncAddress);
    syncAddress();
  }

  document.querySelectorAll('.product-image, .product-image-wrap img, .hero-card img, .table-product img').forEach((img) => {
    img.addEventListener('error', () => {
      img.style.visibility = 'hidden';
      img.parentElement.classList.add('image-fallback');
    }, { once: true });
  });
});
