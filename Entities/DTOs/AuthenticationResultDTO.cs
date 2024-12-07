

using Entities.Common;

namespace Entities.DTOs
{
    public class AuthenticationResultDTO
    {
        public bool Succes { get; private set; }
        public string? Token { get; private set; }
        public string? RefreshToken { get; private set; }
        public string? Message { get; private set; }

        public AuthenticationResultDTO(bool success, string? token = null, string? refreshToken = null, string? message = null)
        {
            Succes = success;
            Token = token;
            RefreshToken = refreshToken;
            Message = message;
        }

        public static AuthenticationResultDTO SuccessResult(string token) => new AuthenticationResultDTO(true, token);
        public static AuthenticationResultDTO SuccessResult(string token, string refreshToken) => new AuthenticationResultDTO(true, token, refreshToken);
        public static AuthenticationResultDTO FailureResult(string message) => new AuthenticationResultDTO(false, message : message);
    }
}
