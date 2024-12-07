

using AutoMapper;
using Entities;
using Entities.Common;
using Entities.DTOs;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Repository;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Services.Auth
{
    public class AuthenticationService : IAuthenticationService
    {
        #region Propierties
        private readonly IMapper _mapper;
        private readonly IUserRepository _userRepository;
        private readonly IRefreshTokenRepository _refreshTokenRepository;
        private readonly IConfiguration _configuration;
        #endregion

        #region CTR
        public AuthenticationService(
            IMapper mapper, IUserRepository userRepository, IConfiguration configuration,
            IRefreshTokenRepository refreshTokenRepository
         )
        {
            _mapper = mapper;
            _userRepository = userRepository;
            _refreshTokenRepository = refreshTokenRepository;
            _configuration = configuration;
        }
        #endregion

        #region Methods
        public async Task<AuthenticationResultDTO?> AuthenticateAsync(string email, string password)
        {
            try
            {
                var user = await _userRepository.GetUserByEmailAsync(email);
                if (user == null || !VerifyPassword(user, password))
                {
                    return AuthenticationResultDTO.FailureResult("User or password invalid");
                }

                string token = GenerateJsonWebToken(user.Id);
                var refreshToken = GenerateRefreshToken(user.Id);

                await _userRepository.SaveRefreshTokenAsync(refreshToken);

                return AuthenticationResultDTO.SuccessResult(token, refreshToken.Token);
            }
            catch (Exception ex)
            {
                return AuthenticationResultDTO.FailureResult("An error occurred during authentication.");
            } 
        }
        public async Task<AuthenticationResultDTO> RegisterUserAsync(string email, string password)
        {
            try
            {
                var existingUser = await _userRepository.GetUserByEmailAsync(email);
                if (existingUser != null)
                {
                    return AuthenticationResultDTO.FailureResult("email already i use");
                }

                var hashedPassword = GetSHA256(password);

                var newUser = new User(email, password);

                await _userRepository.AddUserAsync(newUser);

                var token = GenerateJsonWebToken(newUser.Id);

                //send confirmation acount created
                //send confirmation email

                return AuthenticationResultDTO.SuccessResult(token);
            }
            catch (Exception ex)
            {
                return AuthenticationResultDTO.FailureResult($"An unexpected error occurred: {ex.Message}");
            }

        }
        public async Task<AuthenticationResultDTO> LogoutAsync(int userId, string refreshToken)
        {
            try
            {
                var token = await _userRepository.GetRefreshTokenAsync(userId, refreshToken);
                if (token != null)
                {
                    token.IsRevoked = true;
                    await _userRepository.UpdateRefreshTokenAsync(token);
                }
                return AuthenticationResultDTO.SuccessResult(null);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        public async Task<AuthenticationResultDTO> RefreshTokenAsync(string expiredToken, string refreshToken)
        {
            try
            {
                var principal = GetPrincipalFromExpiredToken(expiredToken);
                var userId = principal?.Claims?.FirstOrDefault(c => c.Type == "id")?.Value;

                var storedRefreshToken = await _refreshTokenRepository.GetRefreshTokenByUserIdAsync(userId);
                if (storedRefreshToken == null || storedRefreshToken.Token.Token != refreshToken || storedRefreshToken.IsExpired)
                {
                    return AuthenticationResultDTO.FailureResult("Invalid refresh token.");
                }

                var newToken = GenerateJsonWebToken(principal);
                var newRefreshToken = GenerateRefreshToken(Convert.ToInt32(userId));

                // Actualizar el refresh token en la base de datos
                storedRefreshToken.Token = newRefreshToken;
                await _refreshTokenRepository.UpdateRefreshTokenAsync(storedRefreshToken);

                return new AuthenticationResultDTO(true, newToken, newRefreshToken.Token);
            }
            catch (Exception ex)
            {
                return AuthenticationResultDTO.FailureResult($"An unexpectad error ocure:{ex.Message}");
            }
        }
        #endregion

        #region Private Methods
        private RefreshToken GenerateRefreshToken(int userId)
        {
            var token = Guid.NewGuid().ToString();

            var refreshToken = new RefreshToken
            {
                Token = token,
                UserId = userId,
                Expiration = DateTime.UtcNow.AddDays(15),
                IsRevoked = false,
                IsUsed = false
            };

            return refreshToken;
        }
        private string GenerateJsonWebToken(int userId)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMonths(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private string GenerateJsonWebToken(ClaimsPrincipal principal)
        {
            var userIdClaim = principal.FindFirst(JwtRegisteredClaimNames.Sub);
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int userId))
            {
                throw new SecurityTokenException("User ID claim is missing or invalid");
            }

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            // Obtener clave secreta y otros datos de configuración
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Configurar el token
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMonths(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private bool VerifyPassword(User user, string password)
        {
            if (string.IsNullOrEmpty(password) || user == null)
            {
                throw new InvalidOperationException("password o usaurio no recibidos correctamente");
            }

            var saltedPassword = user.Salt + password;

            using (var hmac = new System.Security.Cryptography.HMACSHA256())
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(saltedPassword));
                var computedHashString = Convert.ToBase64String(computedHash);

                return computedHashString == user.PasswordHash;
            }
        }
        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])),
                ValidateLifetime = false // Importante: No validamos la expiración en este punto
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            var jwtToken = securityToken as JwtSecurityToken;

            if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Token inválido");

            return principal;
        }
        private string GetSHA256(string password)
        {
            SHA256 sha256 = SHA256.Create();
            ASCIIEncoding encoding = new ASCIIEncoding();
            byte[] stream = null;
            StringBuilder sb = new StringBuilder();
            stream = sha256.ComputeHash(encoding.GetBytes(password));
            for (int i = 0; i < stream.Length; i++) sb.AppendFormat("{0:x2}", stream[i]);
            return sb.ToString();
        }

    }
    #endregion
}
