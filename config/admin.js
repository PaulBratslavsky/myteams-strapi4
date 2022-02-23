module.exports = ({ env }) => ({
  auth: {
    secret: env('ADMIN_JWT_SECRET', '856f11496bdf8e1c51edb697d55ab53c'),
  },
});
