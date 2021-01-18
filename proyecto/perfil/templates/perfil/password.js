var pbkdf2 = require('pbkdf2-sha256');
var validatePassword = function (key, string) {
    var parts = string.split('$');
    var iterations = parts[1];
    var salt = parts[2];
    return pbkdf2(key, new Buffer(salt), iterations, 32).toString('base64') === parts[3];
};

var djangoPass = 'pbkdf2_sha256$150000$1N58DYOFSsRE$Rp7pwt3lfQYXd2YJUHhOzd96LE/pKEvrnE208eI3yaw=';
console.log(validatePassword('tloz.oot1', djangoPass));