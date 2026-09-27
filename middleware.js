function requireAuth(req,res,next){ if(req.session.user) return next(); res.redirect('/login?next='+encodeURIComponent(req.originalUrl)); }
module.exports={requireAuth};
