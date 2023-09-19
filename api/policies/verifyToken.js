const jwt = require('jsonwebtoken');
const secretKey1 = sails.config.secretKey1;

module.exports = async function (req, res, next) {
    const token = req.header('Authorization');

    if(!token) {
        return res.status(401).json({
            error: 'Access denied. No token provided.'
        })
    }

    try {
        const decoded = jwt.verify(token, secretKey1);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(500).json({
            error: 'Invalid Token',
        })
    }
}

/**
 * @api {post} http://localhost:1337/user/login Verify Token
 * @apiName CreateToken
 * @apiGroup Token
 *
 * 
 * @apiParamExample {json} Request-Example:
 *   {
 *     "email": "binhmai@gmail.com",
 *     "password": "binhmai123"
 *   }
 *
 * @apiSuccess {Number} id The new Users-ID.
 * @apiSuccessExample {json} Success-Response:
 *   HTTP/1.1 201 OK
 *   {
 *      "user": {
 *          "createdAt": 1695029777120,
 *          "updatedAt": 1695029777120,
 *          "id": "65081a11ef295b4008866898",
 *          "name": "binhmai",
 *          "email": "binhmai@gmail.com"
 *      },
 *      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NTA4MWExMWVmMjk1YjQwMDg4NjY4OTgiLCJpYXQiOjE2OTUwOTUzMjUsImV4cCI6MTY5NTA5NTQyNX0.YIvrfUScwkQdBGhO_vdB2DwfSyfIvgz73Njb-RIlSvs",
 *      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NTA4MWExMWVmMjk1YjQwMDg4NjY4OTgiLCJpYXQiOjE2OTUwOTUzMjUsImV4cCI6MTY5NzY4NzMyNX0.CYkOzRn2OQHYG6RhbqZ0k4sMB-01xhSDEyz_oPSUkzY"
 *   }
 *
 * @apiError error An error occurred during the login process.
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 500 Internal Server Error
 *   {
 *     "error": "Login Failed!"
 *   }
 */