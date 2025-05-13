document.getElementById('forgot-password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
  
    const email = document.getElementById('email').value;
  
    try {
        const response = await fetch('/forgot-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email }),
        });
  
        const data = await response.json();
  
        if (response.ok) {
            document.getElementById('successMessage').style.display = 'block';
            document.getElementById('successMessage').innerText = 'A password reset link has been sent to your email.';
        } else {
            alert(data.message || 'Error while resetting password. Please try again.');
        }
    } catch (error) {
        console.error('Error during password reset:', error);
        alert('An unexpected error occurred. Please try again later.');
    }
  });
  