using Entities;
using Entities.Common;

namespace Repository
{
    public interface IUserRepository
    {
        Task<User?> GetUserByIdAsync(int id);
        Task<User?> GetUserByEmailAsync(string email);
        Task<IEnumerable<User>> GetAllUsersAsync();
        Task AddUserAsync(User user);
        Task UpdateUserAsync(User user);
        Task DeleteUserAsync(int id);                 
        Task<bool> UserExistsAsync(string email);
        Task<bool> UpdatePasswordAsync(int userId, string newPasswordHash, string newSalt);
        Task<RefreshToken> SaveRefreshTokenAsync(RefreshToken refreshToken);
        Task<RefreshToken> GetRefreshTokenAsync(int userId, string refreshToken);
        Task UpdateRefreshTokenAsync(RefreshToken token);
        Task UpdateRefreshTokenAsync(RefreshToken storedRefreshToken, RefreshToken newRefreshToken);
    }
}
