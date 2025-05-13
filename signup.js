document.getElementById('signup-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  // Collecting form data
  const username = document.getElementById('username').value;
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirm-password').value;

  // Validate empty fields
  if (!username || !email || !password || !confirmPassword) {
    alert('All fields are required!');
    return;
  }

  // Password validation
  if (password !== confirmPassword) {
    alert('Passwords do not match!');
    return;
  }

  // Email validation (Regex pattern to match valid email format)
  const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
  if (!emailRegex.test(email)) {
    alert('Please enter a valid email address!');
    return;
  }

  try {
    // Sending data to the server
    const response = await fetch('/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password }),
    });

    const data = await response.json();

    if (response.ok) {
      // Display success message and redirect to login
      alert(data.message);
      window.location.href = '/login'; // Redirect to login page
    } else {
      // Display error message from the server
      alert(data.message || 'An error occurred during signup');
    }
  } catch (error) {
    console.error('Error during signup:', error);
    alert('Something went wrong. Please try again later.');
  }
});
