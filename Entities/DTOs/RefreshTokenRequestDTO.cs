
using System.ComponentModel.DataAnnotations;


namespace Entities.DTOs
{
    public class RefreshTokenRequestDTO
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}
