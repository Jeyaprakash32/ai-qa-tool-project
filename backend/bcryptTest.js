const bcrypt = require('bcryptjs');
bcrypt.compare('123456', '$2b$12$uGKlSaTD5NV3x9ecQMYdYuGs6CzxOwIZbpgzi/zyOUQkSHBQIngS.', (err, res) => console.log(res));
