
using Entities.Common;
using Entities.DTOs;

namespace Entities
{
    public class User : BaseEntity
    {
        public string FirstName { get; private set; }
        public string LastName { get; private set; }
        public string Email { get; private set; }
        public string? PasswordHash { get; private set; }
        public string? Salt { get; private set; }
        public DateTime LastLogin { get; private set; }
        public bool IsActive { get; private set; }
        public string? Rol { get; private set; }

        public User(string email, string password)
        {
            Email = email;
            PasswordHash = password;
        }

        public void UpdateInfo(UserDTO user)
        {
            if (user == null)
                new ArgumentException("no user recibido");

            FirstName = user.FirstName;
            LastName = user.LastName;
            Email = user.Email;
            Rol = user.Rol;
        }

        public void SetPassword(string password)
        {
            Salt = Convert.ToBase64String(new byte[16]);
            PasswordHash = GenerateHash(password, Salt);
        }

        public bool VerifyPassword(string password)
        {
            var hash = GenerateHash(password, Salt);
            return hash == PasswordHash;
        }

        private string? GenerateHash(string password, string salt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA256())
            {
                var saltedPassword = salt + password;
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(saltedPassword));
                return Convert.ToBase64String(computedHash);
            }
        }
    }
}
