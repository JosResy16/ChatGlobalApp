

using Entities.Common;
using Entities.DTOs;

namespace Services.Auth
{
    public interface IAuthenticationService
    {
        Task<AuthenticationResultDTO> AuthenticateAsync(string email, string password);
        Task<AuthenticationResultDTO> LogoutAsync(int userId, string refreshToken);
        Task<AuthenticationResultDTO> RefreshTokenAsync(string expiredToken, string refreshToken);
        Task<AuthenticationResultDTO> RegisterUserAsync(string email, string password);

    }
}
