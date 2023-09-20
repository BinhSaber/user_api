const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const secretKey1 = sails.config.secretKey1;
const secretKey2 = sails.config.secretKey2;

module.exports = {
    // Register Here
    async create(req, res) {
        try {
            const { name, email, password } = req.allParams();
            // Hash Password
            const hashedPasword = await bcrypt.hash(password, 10);
            // Check required
            if (!email || !password) {
                return res.json({
                    error: 'Email and password are required',
                });
            }
            // Check Email Exists
            const existingEmail = await User.findOne({ email });
            if (existingEmail) {
                return res.json({
                    error: 'Email is already registered!',
                });
            }
            const user = await User.create({ name, email, password: hashedPasword }).fetch();
            res.status(201).json({
                message: `An account has been created for ${user.email} successfully!.`,
            });
        } catch (unused) {
            res.status(500).json({
                error: 'User Register Failed!',
            });
        }
    },
    // Login Here
    async login(req, res) {
        try {
            const { email, password } = req.allParams();
            // Find the user by email
            const user = await User.findOne({ email });
            // Check required
            if (!email || !password) {
                return res.json({
                    error: 'Email and password are required',
                });
            }
            // If the user not found
            if (!user) {
                return res.json({ error: 'User not found!' });
            }
            // Check Password (Compare)
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) {
                return res.json({ error: 'Invalid Password!' });
            }
            // Check user_id
            const existsUser = await Auth.findOne({ 'user_id': user.id });
            if (existsUser) {
                await Auth.destroy({ 'user_id': user.id });
            }
            // Create token
            const token = jwt.sign({ userId: user.id }, secretKey1, { expiresIn: 100 });
            const refreshToken = jwt.sign({ userId: user.id }, secretKey2, { expiresIn: '30d' });

            // Insert data in table Auth
            await Auth.create({ refreshToken: refreshToken, 'user_id': user.id });
            res.json({
                user,
                token,
                refreshToken
            });
        } catch (unused) {
            res.json({
                error: 'Login Failed!',
            });
        }
    },
    // Update Here
    async update(req, res) {
        try {
            const { name, email } = req.allParams();
            const userId = req.user.userId;
            const user = await User.findOne({ id: userId });

            if (!user) {
                return res.status(404).json({
                    error: 'User not found!',
                });
            }
            // Update
            if (name) {
                user.name = name;
            }
            if (email) {
                user.email = email;
            }

            const updatedUser = await User.updateOne({ id: userId }).set({
                name: user.name,
                email: user.email,
            });
            res.json(updatedUser);
        } catch (unused) {
            return res.status(500).json({
                error: 'Update Failed!',
            });
        }
    },
    // Delete Here
    async delete(req, res) {
        try {
            const { id } = req.params;
            const user = await User.findOne({ id: id });
            // Check User
            if (!user) {
                return res.status(404).json({
                    error: 'User not found!',
                });
            }
            await User.destroy({ id: id });
            await Auth.destroy({ 'user_id': id });
            return res.json({
                message: 'Delete Successfully!',
            });
        } catch (unused) {
            return res.status(500).json({
                error: 'Delete Failed!',
            });
        }
    },
    // Refresh Token
    async refreshToken(req, res) {
        try {
            const { refreshToken } = req.body;
            const AuthToken = await Auth.findOne({ refreshToken });

            if (!AuthToken || AuthToken.refreshToken !== refreshToken) {
                return res.status(401).json({
                    error: 'Invalid Token',
                });
            }
            // Verify refresh token
            jwt.verify(refreshToken, secretKey2, async (err, decoded) => {
                if (err) {
                    return res.status(401).json({
                        error: 'Invalid or Expired Refresh Token!',
                    });
                }
                // Create new token
                const newToken = jwt.sign({ userId: decoded.userId }, secretKey1, { expiresIn: 300 });
                res.json({ token: newToken });
            });
        } catch (error) {
            return res.status(500).json({
                error: error.message,
            });
        }
    },
    // Detail User From Token
    async detailToken(req, res) {
        const token = req.headers.authorization;

        if (!token) {
            return res.status(404).json({
                error: 'Invalid Token',
            });
        }

        try {
            const decodedToken = jwt.verify(token, secretKey1);
            // Extract user infor
            const userId = decodedToken.sub;
            const userInfor = await User.find({ id: userId }).limit(1);

            if (!userInfor) {
                return res.status(404).json({
                    error: 'User Not Found',
                });
            }

            // Attach the user information to the request for further use
            req.me = userInfor;

            res.json(userInfor);
        } catch (error) {
            console.error(error);
            return res.status(500).json({
                error: error.message,
            });
        }
    },
    // Find User By Id
    async find(req, res) {
        const { name } = req.params;
        try {
            const user = await User.find({ name: { 'contains': name } });
            if (!user || user.length === 0) {
                return res.status(404).json({
                    error: 'User Not Found',
                });
            }
            res.json(user);
        } catch (error) {
            return res.status(500).json({
                error: error.message,
            });
        }
    },
    // User Detail
    async detail(req, res) {
        const { id } = req.params;
        try {
            const user = await User.findOne({ id: id });
            if (!user) {
                return res.json({
                    error: 'User Not Found',
                });
            }
            res.json(user);
        } catch (error) {
            return res.json({
                error: error.message,
            });
        }
    },
};

/**
 * @api {post} http://localhost:1337/user/register Register a new user
 * @apiName CreateUser
 * @apiGroup User
 *
 * @apiBody {String} name        Name of the User.
 * @apiBody {String} email       Email of the User.
 * @apiBody {String} password    Password of the User.
 *
 * @apiParamExample {json} Request-Example:
 *   {
 *     "name": "BinhSaber",
 *     "email": "binhmai@gmail.com",
 *     "password": "binhmai123"
 *   }
 *
 * @apiSuccess {Number} id The new Users-ID.
 * @apiSuccessExample {json} Success-Response:
 *   HTTP/1.1 201 OK
 *   {
 *      "message": "An account has been created for binhmai@gmail.com successfully!."
 *   }
 *
 * @apiError emailAlreadyUse The specified email address is already in use.
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 400 Bad Request
 *   {
 *     "error": "Email is already registered!"
 *   }
 */

/**
 * @api {post} http://localhost:1337/user/login Login
 * @apiName Login
 * @apiGroup User
 *
 * @apiBody {String} email                Email of User.
 * @apiBody {String} password             Password of the User.
 *
 * @apiParamExample {json} Request-Example:
 *   {
 *     "email": "binhmai@gmail.com",
 *     "password": "binhmai123"
 *   }
 *
 * @apiSuccess {Number} id The Users-ID.
 * @apiSuccess {String} name Name of the User.
 * @apiSuccess {String} email Email of the User.
 * @apiSuccessExample {json} Success-Response:
 *   HTTP/1.1 200 OK
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
 * @apiError notAUser User not found.
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 404 Bad Request
 *   {
 *     "error": "User not found",
 *   }
 *
 * @apiError error An error occurred during the login process.
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 401 Internal Server Error
 *   {
 *     "error": "Login failed!",
 *   }
 *
 */

/**
 * @api {put} http://localhost:1337/user/update Update User
 * @apiName Update User
 * @apiGroup User
 *
 * @apiBody {String} name             Name of the User.
 * @apiBody {String} email                Email of User.
 *
 * @apiParamExample {json} Request-Example:
 *   {
 *     "name": "binhmai",
 *     "email": "binhmai1@gmail.com"
 *   }
 *
 * @apiSuccess {Number} id The Users-ID.
 * @apiSuccessExample {json} Success-Response:
 *   HTTP/1.1 200 OK
 *   {
 *      "createdAt": 1695095875795,
 *      "updatedAt": 1695095908535,
 *      "id": "65091c435b5a47446853c6b7",
 *      "name": "binhmai",
 *      "email": "binhmai1@gmail.com"
 *   }
 *
 * @apiError notAUser User not found.
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 404 Bad Request
 *   {
 *     "error": "User not found"
 *   }
 *
 * @apiError error An error occurred during the update process.
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 400 Internal Server Error
 *   {
 *     "error": "Update Failed!"
 *   }
 */

/**
 * @api {delete} http://localhost:1337/user/delete/:id Delete User
 * @apiName Delete User
 * @apiGroup User
 *
 * @apiParam {String} id Id of the user
 *
 * @apiParamExample {json} Request-Example:
 *   http://localhost:1337/user/delete/6509535fe8ed973bf8f52d1b
 *
 * @apiSuccessExample {json} Success-Response:
 *   HTTP/1.1 200 OK
 *   {
 *      "message": "Delete Successfully!"
 *   }
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 404 Bad Request
 *   {
 *     "error": "User not found"
 *   }
 *
 * @apiError error An error occurred during the delete process.
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 400 Internal Server Error
 *   {
 *     "error": "Delete Failed!"
 *   }
 */

/**
 * @api {get} http://localhost:1337/user/detail/:id Detail User
 * @apiName Detail User
 * @apiGroup User
 *
 * @apiParam {String} id  Id of the User.
 *
 * @apiParamExample {json} Request-Example:
 *  http://localhost:1337/user/detail/650961f52c8eba69f0e8f716
 *
 * @apiSuccess {String} id    Id of the user.
 * @apiSuccess {String} name  Name of the user.
 * @apiSuccess {String} email Email of the user.
 * @apiSuccessExample {json} Success-Response:
 *   HTTP/1.1 200 OK
 *   {
 *      "createdAt": 1695113717637,
 *      "updatedAt": 1695113717637,
 *      "id": "650961f52c8eba69f0e8f716",
 *      "name": "binhmai",
 *      "email": "binhmai@gmail.com"
 *   }
 *
 * @apiError notAUser User not found.
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 404 Bad Request
 *   {
 *     "error": "User not found"
 *   }
 */

/**
 * @api {get} http://localhost:1337/user/infor Get Infor User From Token
 * @apiName Decode
 * @apiGroup Token
 *
 *
 * @apiParamExample {json} Request-Example:
 *   Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2NTAxMjhhMjJmZWIwNDA4ZmMwOTVkNjUiLCJpc3MiOiJVc2VyIEFQSSIsImlhdCI6MTY5NDY1OTgxNSwiZXhwIjoxNjk0NjYwMTE1fQ.uESpm4YnfiFRxRvkz8o89aPMFwBgPKu8QNsQeP47vmY
 *
 * @apiSuccess {string} token The User's Token.
 * @apiSuccessExample {json} Success-Response:
 *   HTTP/1.1 201 OK
 *   {
 *    "data": {
 *       "createdAt": 1694574753910,
 *       "updatedAt": 1694593104244,
 *       "id": "650128a22feb0408fc095d65",
 *       "name": "binhmai",
 *       "email": "binhmai@gmail.com"
 *    },
 *   }
 *
 *
 * @apiError invalidToken Invalid Token.
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 404 Bad Request
 *   {
 *     "error": "Invalid Token",
 *   }
 *
 *
 * @apiError error An error occurred during the get process.
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 500 Internal Server Error
 *   {
 *     "error": "User Not Found"
 *   }
 */

/**
 * @api {post} http://localhost:1337/user/refreshToken Refresh Token
 * @apiName RefreshToken
 * @apiGroup Token
 *
 *
 * @apiParamExample {json} Request-Example:
 *   {
 *     "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NTA5MWM0MzViNWE0NzQ0Njg1M2M2YjciLCJpYXQiOjE2OTUwOTYzNTUsImV4cCI6MTY5NTA5NjY1NX0.dGhxivZyuAIVwwWjXkW5DBDffWgNznejloy4f5HDRAk",
 *   }
 *
 * @apiSuccess {Number} id The new Users-ID.
 * @apiSuccessExample {json} Success-Response:
 *   HTTP/1.1 201 OK
 *   {
 *    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiaW5obWFpQGdtYWlsLmNvbSIsImlzcyI6IlVzZXIgQVBJIiwiaWF0IjoxNjk0NTk5MzIwLCJleHAiOjE2OTQ1OTk2MjB9.od5Yxaoq4ZG2d4L8p77_64tUbL_lFfi1PzJfB9o4hSQ"
 *   }
 *
 *
 * @apiError error An error occurred during the get new token process.
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 500 Internal Server Error
 *   {
 *     "error": "Invalid Token"
 *   }
 */

/**
 * @api {get} http://localhost:1337/user/find/:name Find User
 * @apiName Find User
 * @apiGroup User
 *
 * @apiParam {String} name Name of the User.
 *
 * @apiParamExample {json} Request-Example:
 *   http://localhost:1337/user/find/b
 *
 *
 * @apiSuccess {String} id     Id of the user
 * @apiSuccess {String} name   Name of the user.
 * @apiSuccess {String} email  Email of the user.
 *
 * @apiSuccessExample {json} Success-Response:
 *   HTTP/1.1 200 OK
 *   [
 *       {
 *           "createdAt": 1695098229437,
 *           "updatedAt": 1695098229437,
 *           "id": "65092575fa31a35a9099c769",
 *           "name": "binhmai",
 *           "email": "binhmai1@gmail.com"
 *       },
 *       {
 *           "createdAt": 1695104582207,
 *           "updatedAt": 1695104687739,
 *           "id": "65093e463beb7562b0a68249",
 *           "name": "binhmai",
 *           "email": "binhmai2@gmail.com"
 *       },
 *       {
 *           "createdAt": 1695104590605,
 *           "updatedAt": 1695104590605,
 *           "id": "65093e4e3beb7562b0a6824a",
 *           "name": "binhmai",
 *           "email": "binhmai@gmail.com"
 *       }
 *   ]
 *
 * @apiErrorExample {json} Error-Response:
 *   HTTP/1.1 404 Bad Request
 *   {
 *     "error": "User Not Found"
 *   }
 *
 */
