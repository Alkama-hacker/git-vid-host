/* Demo interaction — travels inside the encrypted content chunks. */
(function () {
  'use strict';

  var btn = document.getElementById('cta');
  var hint = document.getElementById('hint');
  var hits = 0;

  var messages = [
    'The script you are running was never in page source.',
    'Everything above arrived as AES-256-GCM chunks.',
    'The defence engine is sealed in five more layers.',
    'Nice try, but the source is still empty. 😂'
  ];

  if (btn) {
    btn.addEventListener('click', function () {
      var secret = document.createElement('span');
      secret.className = 'secret';
      secret.textContent = 'chunk #' + (hits + 1) + ' decrypted';
      if (hint) {
        hint.textContent = messages[hits % messages.length];
        if (!hint.querySelector('.secret')) hint.appendChild(secret);
        else hint.querySelector('.secret').textContent = secret.textContent;
      }
      hits++;
    });
  }

  var form = document.getElementById('form');
  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (hint) hint.textContent = 'Form captured locally — wire it to your backend.';
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.body.setAttribute('data-ready', '1');
  });
})();
