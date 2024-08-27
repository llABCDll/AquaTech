const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'thanadol186@gmail.com',
        pass: 'eaog thuc ppgv teil'
    }
});

module.exports = transporter;
