

using AutoMapper;
using Entities;
using Entities.Common;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Repository;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Services.Auth
{
    public class Authentication
    {
        private readonly IMapper _mapper;
        private readonly IUserRepository _userRepository;
        private readonly IConfiguration _configuration;

        public Authentication(IMapper mapper, IUserRepository userRepository, IConfiguration configuration)
        {
            _mapper = mapper;
            _userRepository = userRepository;
            _configuration = configuration;
        }

        public async Task<string?> AuthenticateAsync(string email, string password)
        {
            var user = await _userRepository.GetUserByEmailAsync(email);
            if(user == null || !VerifyPassword(user ,password))
            {
                return null;
            }

            return GenerateJsonWebToken(user);
        }

        public async Task<(string token, string refreshToken)> LoginAsync(string email, string password)
        {
            var user = await _userRepository.GetUserByEmailAsync(email);
            if (user == null || !user.VerifyPassword(password))
                throw new UnauthorizedAccessException("Invalid credentials.");

            var token = GenerateJsonWebToken(user);
            var refreshToken = GenerateRefreshToken();
            refreshToken.UserId = user.Id;

            await _userRepository.SaveRefreshTokenAsync(refreshToken);

            return (token, refreshToken.Token);
        }

        public async Task LogoutAsync(int userId, string refreshToken)
        {
            var token = await _userRepository.GetRefreshTokenAsync(userId, refreshToken);
            if (token != null)
            {
                token.IsRevoked = true;
                await _userRepository.UpdateRefreshTokenAsync(token);
            }
        }

        private object GetPrincipalFromExpiredToken(string token)
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

        private RefreshToken GenerateRefreshToken()
        {
            var randomBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomBytes),
                Expiration = DateTime.UtcNow.AddDays(15)
            };
        }

        private string GenerateJsonWebToken(User user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Email)
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
    }
}
