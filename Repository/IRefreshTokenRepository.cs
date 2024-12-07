using Entities;
using Entities.Common;


namespace Repository
{
    public interface IRefreshTokenRepository
    {
        public Task<StoredRefreshToken> GetRefreshTokenByUserIdAsync(string userId);
        public Task<StoredRefreshToken> UpdateRefreshTokenAsync(StoredRefreshToken storedToken);
    }
}
