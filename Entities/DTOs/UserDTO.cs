using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entities.DTOs
{
    public class UserDTO
    {
        public int Id { get; set; }
        public string FirstName { get; private set; }
        public string LastName { get; private set; }
        public string Email { get; private set; }
        public string? Password { get; private set; }
        public string RefreshToken { get; set; }
        public string? Salt { get; private set; }
        public DateTime LastLogin { get; private set; }
        public bool IsActive { get; private set; }
        public string? Rol { get; private set; }
    }
}
