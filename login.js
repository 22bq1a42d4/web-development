document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault(); // Prevent default form submission behavior

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  // Log the login request data for debugging
  console.log('Login request:', { username, password });

  try {
    const response = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    const data = await response.json();

    if (response.ok) {
      // Store the JWT token in localStorage or sessionStorage
      localStorage.setItem('authToken', data.token);

      // Log success and redirect
      console.log('Login successful, token:', data.token);
      window.location.href = '/'; // Ensure this is the correct redirection page
    } else {
      // Alert the error message from the server
      alert(data.message || 'Login failed');
    }
  } catch (error) {
    console.error('Error logging in:', error);

    // Additional error handling for unknown errors (e.g., network errors)
    alert('An error occurred while logging in. Please try again later.');
  }
});
