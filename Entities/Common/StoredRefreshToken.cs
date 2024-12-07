using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entities.Common
{
    public class StoredRefreshToken
    {
        public int Id { get; set; }
        public RefreshToken Token { get; set; }
        public int UserId { get; set; }
        public DateTime Expiration { get; set; }
        public bool IsExpired { get; set; }
        public bool IsRevoked { get; set; }
    }
}
