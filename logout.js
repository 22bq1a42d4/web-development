document.getElementById('logout-button').addEventListener('click', () => {
    localStorage.removeItem('authToken'); // Remove token
    window.location.href = '/'; // Redirect to the login page
  });
  