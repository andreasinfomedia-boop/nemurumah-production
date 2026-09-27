class SQLiteSessionStore {
  constructor(db) {
    this.db = db;
    this.getStmt = db.prepare('SELECT sess, expire FROM sessions WHERE sid=?');
    this.setStmt = db.prepare(`INSERT INTO sessions(sid,sess,expire) VALUES (?,?,?)
      ON CONFLICT(sid) DO UPDATE SET sess=excluded.sess, expire=excluded.expire`);
    this.destroyStmt = db.prepare('DELETE FROM sessions WHERE sid=?');
    this.touchStmt = db.prepare('UPDATE sessions SET expire=? WHERE sid=?');
    this.cleanupStmt = db.prepare('DELETE FROM sessions WHERE expire <= ?');
  }
  get(sid, cb) {
    try {
      const row = this.getStmt.get(sid);
      if (!row || row.expire <= Date.now()) return cb(null, null);
      cb(null, JSON.parse(row.sess));
    } catch (e) { cb(e); }
  }
  set(sid, sess, cb) {
    try {
      const cookie = sess.cookie || {};
      const expire = cookie.expires ? new Date(cookie.expires).getTime() : Date.now() + 8 * 60 * 60 * 1000;
      this.setStmt.run(sid, JSON.stringify(sess), expire);
      cb && cb(null);
    } catch (e) { cb && cb(e); }
  }
  destroy(sid, cb) {
    try { this.destroyStmt.run(sid); cb && cb(null); } catch (e) { cb && cb(e); }
  }
  touch(sid, sess, cb) {
    try {
      const cookie = sess.cookie || {};
      const expire = cookie.expires ? new Date(cookie.expires).getTime() : Date.now() + 8 * 60 * 60 * 1000;
      this.touchStmt.run(expire, sid); cb && cb(null);
    } catch (e) { cb && cb(e); }
  }
  cleanup() { this.cleanupStmt.run(Date.now()); }
}
module.exports = SQLiteSessionStore;
