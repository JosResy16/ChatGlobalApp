using Entities.DTOs;
using Microsoft.AspNetCore.Mvc;
using Services.Auth;
using System.Net;

namespace Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthenticationService _authService;
        public AuthController(IAuthenticationService authService)
        {
            _authService = authService;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] LoginDTO loginDTO)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var response = await _authService.AuthenticateAsync(loginDTO.Correo, loginDTO.Clave);
                if(!response.Succes)
                    return Unauthorized(new {Message = response.Message});

                return Ok(response);

            }
            catch
            {
                return StatusCode(500, new { Message = "An unexpected error occurred." });
            }
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserDTO userDTO)
        {
            try
            {
                var result = await _authService.RegisterUserAsync(userDTO.Email, userDTO.Password);
                if(!result.Succes)
                    return BadRequest(result.Message);

                return Ok(result);
            }
            catch
            {
                return StatusCode(500, new { Message = "An unexpected error ocurred" });
            }
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutRequestDTO logoutRequest)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var userIdClaim = HttpContext.User.FindFirst("sub");
                if (userIdClaim == null)
                    return Unauthorized(new { Message = "User ID not found in token" });

                int userId = int.Parse(userIdClaim.Value);

                var result = await _authService.LogoutAsync(userId, logoutRequest.RefreshToken);
                if (!result.Succes)
                {
                    return Unauthorized(new {Message = result.Message});
                }

                return Ok(new {Message = "Logout Successful"});
            }
            catch
            {
                return StatusCode(500, new { Message = "An unexpected error ocurred" });
            }
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDTO request)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var accesToken = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ","");
                if (string.IsNullOrWhiteSpace(accesToken))
                {
                    return Unauthorized(new { Message = "Access token is required" });
                }

                var result = await _authService.RefreshTokenAsync(accesToken, request.RefreshToken);
                if(!result.Succes)
                {
                    return Unauthorized(new { Message = result.Message });
                }

                return Ok(new { Token = result.Token, RefreshToken = result.RefreshToken });
            }
            catch
            {
                return StatusCode(500, new { Message = "An unexpected error ocurred" });
            }
        }
    }
}
