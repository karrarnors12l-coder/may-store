const express=require('express');
const session=require('express-session');
const bcrypt=require('bcryptjs');
const Database=require('better-sqlite3');
const path=require('path');
const crypto=require('crypto');

const app=express();
const PORT=process.env.PORT||3000;
const db=new Database(path.join(__dirname,'store.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
app.use(express.json({limit:'8mb'}));
app.use(express.urlencoded({extended:true,limit:'8mb'}));
app.set('trust proxy',1);
app.use(session({secret:process.env.SESSION_SECRET||'CHANGE_ME_USE_A_LONG_RANDOM_SECRET',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:1000*60*60*24*7}}));

function init(){
 db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,customer_code TEXT UNIQUE NOT NULL,name TEXT DEFAULT '',points INTEGER NOT NULL DEFAULT 10000,role TEXT NOT NULL DEFAULT 'customer',avatar TEXT DEFAULT '',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,description TEXT DEFAULT '',price_points INTEGER NOT NULL,stock INTEGER NOT NULL DEFAULT 0,category TEXT DEFAULT '',image TEXT DEFAULT '',active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,total_points INTEGER NOT NULL,subtotal_points INTEGER NOT NULL,discount_points INTEGER NOT NULL DEFAULT 0,coupon_code TEXT DEFAULT '',status TEXT NOT NULL DEFAULT 'new',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id));
 CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL,product_id INTEGER NOT NULL,name TEXT NOT NULL,price_points INTEGER NOT NULL,qty INTEGER NOT NULL,FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,FOREIGN KEY(product_id) REFERENCES products(id));
 CREATE TABLE IF NOT EXISTS points_history(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,amount INTEGER NOT NULL,type TEXT NOT NULL,note TEXT DEFAULT '',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
 CREATE TABLE IF NOT EXISTS coupons(id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT UNIQUE NOT NULL,type TEXT NOT NULL,value INTEGER NOT NULL,min_points INTEGER NOT NULL DEFAULT 0,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,title TEXT NOT NULL,message TEXT NOT NULL,read INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);`);
 const admin=db.prepare('SELECT id FROM users WHERE username=?').get('admin');
 if(!admin){db.prepare('INSERT INTO users(username,password_hash,customer_code,name,points,role) VALUES(?,?,?,?,?,?)').run('admin',bcrypt.hashSync('123456',10),'ADMIN-0001','المدير',0,'admin');}
 const count=db.prepare('SELECT COUNT(*) c FROM products').get().c;
 if(!count){const ins=db.prepare('INSERT INTO products(name,description,price_points,stock,category,image) VALUES(?,?,?,?,?,?)'); const seed=[['سيروم فيتامين C','سيروم للعناية بالبشرة ومنحها إشراقة.',2500,12,'عناية بالبشرة',''],['واقي شمس','واقي شمس للاستخدام اليومي.',3500,8,'عناية بالبشرة',''],['مرطب للبشرة','مرطب خفيف للاستخدام اليومي.',1800,20,'مرطبات',''],['غسول للوجه','غسول لطيف للتنظيف اليومي.',2200,0,'تنظيف',''],['تونر مرطب','تونر خفيف للعناية اليومية.',1600,15,'تونر',''],['سيروم نياسيناميد','سيروم مناسب للعناية بالبشرة.',2800,10,'سيرومات',''],['كريم مرطب','كريم مرطب للاستخدام اليومي.',3000,7,'مرطبات',''],['ماسك للوجه','ماسك عناية للبشرة.',1900,9,'ماسكات','']]; seed.forEach(x=>ins.run(...x));}
}
init();

function publicUser(u){return {type:'user',id:u.id,username:u.username,name:u.name,customer_code:u.customer_code,points:u.points,avatar:u.avatar||'',role:u.role};}
function requireUser(req,res,next){const id=req.session.userId;if(!id)return res.status(401).json({error:'يجب تسجيل الدخول'});const u=db.prepare('SELECT * FROM users WHERE id=?').get(id);if(!u)return res.status(401).json({error:'انتهت الجلسة'});req.user=u;next();}
function requireAdmin(req,res,next){const id=req.session.userId;if(!id)return res.status(401).json({error:'يجب تسجيل الدخول'});const u=db.prepare('SELECT * FROM users WHERE id=?').get(id);if(!u||u.role!=='admin')return res.status(403).json({error:'صلاحية المدير مطلوبة'});req.user=u;next();}

app.post('/api/auth/register',(req,res)=>{try{const username=String(req.body.username||'').trim();const password=String(req.body.password||'');if(username.length<3||password.length<6)return res.status(400).json({error:'اسم المستخدم 3 أحرف على الأقل وكلمة المرور 6 أحرف على الأقل'});const code='CUS-'+crypto.randomBytes(3).toString('hex').toUpperCase();const info=db.prepare('INSERT INTO users(username,password_hash,customer_code,points) VALUES(?,?,?,?)').run(username,bcrypt.hashSync(password,10),code,10000);db.prepare('INSERT INTO points_history(user_id,amount,type,note) VALUES(?,?,?,?)').run(info.lastInsertRowid,10000,'earn','رصيد البداية');req.session.userId=info.lastInsertRowid;res.json({ok:true,user:publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid))});}catch(e){res.status(400).json({error:e.message.includes('UNIQUE')?'اسم المستخدم مستخدم مسبقاً':e.message});}});
app.post('/api/auth/login',(req,res)=>{const username=String(req.body.username||'').trim();const password=String(req.body.password||'');const u=db.prepare('SELECT * FROM users WHERE username=?').get(username);if(!u||!bcrypt.compareSync(password,u.password_hash))return res.status(401).json({error:'اسم المستخدم أو كلمة المرور غير صحيحة'});req.session.userId=u.id;res.json(publicUser(u));});
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',requireUser,(req,res)=>res.json(publicUser(req.user)));
app.get('/api/products',(req,res)=>res.json(db.prepare('SELECT id,name,description,price_points,stock,category,image FROM products WHERE active=1 ORDER BY id DESC').all()));

app.post('/api/orders',requireUser,(req,res)=>{
 const items=Array.isArray(req.body.items)?req.body.items:[]; if(!items.length)return res.status(400).json({error:'السلة فارغة'});
 const tx=db.transaction(()=>{
  let subtotal=0; const rows=[];
  for(const raw of items){const id=Number(raw.productId),qty=Number(raw.qty);if(!Number.isInteger(qty)||qty<1)throw Error('كمية غير صحيحة');const p=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(id);if(!p)throw Error('المنتج غير موجود');if(p.stock<qty)throw Error(`المخزون غير كافٍ للمنتج: ${p.name}`);subtotal+=p.price_points*qty;rows.push({p,qty});}
  const couponCode=String(req.body.coupon_code||'').trim().toUpperCase();
  let discount=0; if(couponCode){const c=db.prepare('SELECT * FROM coupons WHERE code=? AND active=1').get(couponCode);if(!c)throw Error('الكوبون غير صالح');if(subtotal<c.min_points)throw Error('الحد الأدنى لاستخدام الكوبون غير متحقق');discount=c.type==='percent'?Math.min(subtotal,Math.floor(subtotal*c.value/100)):Math.min(subtotal,c.value);}
  const total=subtotal-discount;
  if(req.user.points<total)throw Error('نقاطك غير كافية لإتمام الطلب');
  const order=db.prepare('INSERT INTO orders(user_id,total_points,subtotal_points,discount_points,coupon_code,status) VALUES(?,?,?,?,?,?)').run(req.user.id,total,subtotal,discount,couponCode,'new');
  const ins=db.prepare('INSERT INTO order_items(order_id,product_id,name,price_points,qty) VALUES(?,?,?,?,?)');const upd=db.prepare('UPDATE products SET stock=stock-?,updated_at=CURRENT_TIMESTAMP WHERE id=?');
  rows.forEach(x=>{ins.run(order.lastInsertRowid,x.p.id,x.p.name,x.p.price_points,x.qty);upd.run(x.qty,x.p.id);});
  db.prepare('UPDATE users SET points=points-? WHERE id=?').run(total,req.user.id);
  db.prepare('INSERT INTO points_history(user_id,amount,type,note) VALUES(?,?,?,?)').run(req.user.id,-total,'spend',`شراء الطلب #${order.lastInsertRowid}`);
  db.prepare('INSERT INTO notifications(user_id,title,message) VALUES(?,?,?)').run(req.user.id,'تم إنشاء الطلب',`تم إنشاء طلبك رقم #${order.lastInsertRowid}`);
  return Number(order.lastInsertRowid);
 });
 try{res.json({ok:true,orderId:tx});}catch(e){res.status(400).json({error:e.message});}
});

app.get('/api/orders',requireUser,(req,res)=>{const orders=db.prepare('SELECT id,total_points,subtotal_points,discount_points,coupon_code,status,created_at FROM orders WHERE user_id=? ORDER BY id DESC').all(req.user.id);for(const o of orders)o.items=db.prepare('SELECT product_id,name,price_points,qty FROM order_items WHERE order_id=?').all(o.id);res.json(orders);});
app.get('/api/points/history',requireUser,(req,res)=>res.json(db.prepare('SELECT amount,type,note,created_at FROM points_history WHERE user_id=? ORDER BY id DESC').all(req.user.id)));
app.get('/api/notifications',requireUser,(req,res)=>res.json(db.prepare('SELECT id,title,message,read,created_at FROM notifications WHERE user_id=? ORDER BY id DESC').all(req.user.id)));
app.post('/api/notifications/read',requireUser,(req,res)=>{if(req.body.id)db.prepare('UPDATE notifications SET read=1 WHERE id=? AND user_id=?').run(Number(req.body.id),req.user.id);else db.prepare('UPDATE notifications SET read=1 WHERE user_id=?').run(req.user.id);res.json({ok:true});});


// Customer extras
app.get('/api/coupons',requireUser,(req,res)=>res.json(db.prepare('SELECT code,type,value,min_points,active FROM coupons WHERE active=1 ORDER BY id DESC').all()));
app.post('/api/coupons/validate',requireUser,(req,res)=>{
 const code=String(req.body.code||'').trim().toUpperCase(); const subtotal=Number(req.body.subtotal||0);
 const c=db.prepare('SELECT code,type,value,min_points FROM coupons WHERE code=? AND active=1').get(code);
 if(!c)return res.status(404).json({error:'الكوبون غير موجود أو متوقف'});
 if(subtotal<c.min_points)return res.status(400).json({error:`الحد الأدنى لاستخدام الكوبون هو ${c.min_points.toLocaleString()} نقطة`});
 const discount=c.type==='percent'?Math.min(subtotal,Math.floor(subtotal*c.value/100)):Math.min(subtotal,c.value);
 res.json({ok:true,coupon:c,discount});
});
app.patch('/api/me/profile',requireUser,(req,res)=>{
 const name=String(req.body.name??req.user.name??'').trim(); const avatar=String(req.body.avatar??req.user.avatar??'');
 if(avatar.length>6*1024*1024)return res.status(400).json({error:'الصورة كبيرة جداً'});
 db.prepare('UPDATE users SET name=?,avatar=? WHERE id=?').run(name,avatar,req.user.id);
 res.json(publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id)));
});
app.post('/api/orders/:id/cancel',requireUser,(req,res)=>{
 const id=Number(req.params.id); const tx=db.transaction(()=>{
  const o=db.prepare('SELECT * FROM orders WHERE id=? AND user_id=?').get(id,req.user.id);
  if(!o)throw Error('الطلب غير موجود'); if(['cancelled','completed'].includes(o.status))throw Error('لا يمكن إلغاء هذا الطلب');
  const items=db.prepare('SELECT * FROM order_items WHERE order_id=?').all(id);
  for(const it of items)db.prepare('UPDATE products SET stock=stock+?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(it.qty,it.product_id);
  db.prepare('UPDATE users SET points=points+? WHERE id=?').run(o.total_points,req.user.id);
  db.prepare('INSERT INTO points_history(user_id,amount,type,note) VALUES(?,?,?,?)').run(req.user.id,o.total_points,'refund',`استرجاع الطلب #${id}`);
  db.prepare('UPDATE orders SET status=? WHERE id=?').run('cancelled',id);
  db.prepare('INSERT INTO notifications(user_id,title,message) VALUES(?,?,?)').run(req.user.id,'تم إلغاء الطلب',`تم إلغاء طلبك رقم #${id} وإرجاع ${o.total_points} نقطة`);
 });
 try{tx();res.json({ok:true});}catch(e){res.status(400).json({error:e.message});}
});

// Admin API
app.post('/api/admin/products',requireAdmin,(req,res)=>{const b=req.body;const r=db.prepare('INSERT INTO products(name,description,price_points,stock,category,image,active) VALUES(?,?,?,?,?,?,?)').run(String(b.name||'منتج'),String(b.description||''),Number(b.price_points||0),Number(b.stock||0),String(b.category||''),String(b.image||''),b.active===false?0:1);res.json({ok:true,id:r.lastInsertRowid});});
app.put('/api/admin/products/:id',requireAdmin,(req,res)=>{const b=req.body;const r=db.prepare('UPDATE products SET name=?,description=?,price_points=?,stock=?,category=?,image=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(String(b.name||''),String(b.description||''),Number(b.price_points||0),Number(b.stock||0),String(b.category||''),String(b.image||''),b.active===false?0:1,Number(req.params.id));res.json({ok:r.changes>0});});
app.delete('/api/admin/products/:id',requireAdmin,(req,res)=>{const r=db.prepare('UPDATE products SET active=0,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(Number(req.params.id));res.json({ok:r.changes>0});});
app.get('/api/admin/products',requireAdmin,(req,res)=>res.json(db.prepare('SELECT * FROM products ORDER BY id DESC').all()));
app.get('/api/admin/orders',requireAdmin,(req,res)=>{const rows=db.prepare(`SELECT o.*,u.username,u.customer_code FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC`).all();for(const o of rows)o.items=db.prepare('SELECT * FROM order_items WHERE order_id=?').all(o.id);res.json(rows);});
app.patch('/api/admin/orders/:id',requireAdmin,(req,res)=>{const status=String(req.body.status||'new');if(!['new','processing','completed','cancelled'].includes(status))return res.status(400).json({error:'حالة غير صحيحة'});const r=db.prepare('UPDATE orders SET status=? WHERE id=?').run(status,Number(req.params.id));res.json({ok:r.changes>0});});
app.get('/api/admin/users',requireAdmin,(req,res)=>res.json(db.prepare('SELECT id,username,name,customer_code,points,role,avatar,created_at FROM users WHERE role="customer" ORDER BY id DESC').all()));
app.patch('/api/admin/users/:id/points',requireAdmin,(req,res)=>{const amount=Number(req.body.amount);if(!Number.isInteger(amount))return res.status(400).json({error:'قيمة النقاط غير صحيحة'});const tx=db.transaction(()=>{db.prepare('UPDATE users SET points=points+? WHERE id=? AND role="customer"').run(amount,Number(req.params.id));db.prepare('INSERT INTO points_history(user_id,amount,type,note) VALUES(?,?,?,?)').run(Number(req.params.id),amount,amount>=0?'earn':'adjust','تعديل من المدير');});tx();res.json({ok:true});});

app.post('/api/admin/users',requireAdmin,(req,res)=>{try{const username=String(req.body.username||'').trim();const password=String(req.body.password||'');const name=String(req.body.name||'').trim();const customerCode=String(req.body.customer_code||('CUS-'+crypto.randomBytes(3).toString('hex').toUpperCase())).trim();const points=Math.max(0,Number(req.body.points||0));if(username.length<3||password.length<6)return res.status(400).json({error:'بيانات الحساب غير صحيحة'});const r=db.prepare('INSERT INTO users(username,password_hash,customer_code,name,points,role) VALUES(?,?,?,?,?,?)').run(username,bcrypt.hashSync(password,10),customerCode,name,points,'customer');if(points)db.prepare('INSERT INTO points_history(user_id,amount,type,note) VALUES(?,?,?,?)').run(r.lastInsertRowid,points,'earn','إنشاء الحساب من المدير');res.json({ok:true,id:r.lastInsertRowid});}catch(e){res.status(400).json({error:e.message.includes('UNIQUE')?'اسم المستخدم أو رمز الزبون مستخدم مسبقاً':e.message});}});
app.delete('/api/admin/users/:id',requireAdmin,(req,res)=>{const r=db.prepare('DELETE FROM users WHERE id=? AND role="customer"').run(Number(req.params.id));res.json({ok:r.changes>0});});
app.get('/api/admin/users/:id/history',requireAdmin,(req,res)=>res.json(db.prepare('SELECT amount,type,note,created_at FROM points_history WHERE user_id=? ORDER BY id DESC').all(Number(req.params.id))));
app.get('/api/admin/coupons',requireAdmin,(req,res)=>res.json(db.prepare('SELECT * FROM coupons ORDER BY id DESC').all()));
app.post('/api/admin/coupons',requireAdmin,(req,res)=>{try{const b=req.body;const code=String(b.code||'').trim().toUpperCase();const type=b.type==='percent'?'percent':'points';const value=Math.max(0,Number(b.value||0));const min=Math.max(0,Number(b.min_points||0));const r=db.prepare('INSERT INTO coupons(code,type,value,min_points,active) VALUES(?,?,?,?,?)').run(code,type,value,min,b.active===false?0:1);res.json({ok:true,id:r.lastInsertRowid});}catch(e){res.status(400).json({error:e.message.includes('UNIQUE')?'الكوبون موجود مسبقاً':e.message});}});
app.put('/api/admin/coupons/:id',requireAdmin,(req,res)=>{const b=req.body;const r=db.prepare('UPDATE coupons SET code=?,type=?,value=?,min_points=?,active=? WHERE id=?').run(String(b.code||'').trim().toUpperCase(),b.type==='percent'?'percent':'points',Math.max(0,Number(b.value||0)),Math.max(0,Number(b.min_points||0)),b.active===false?0:1,Number(req.params.id));res.json({ok:r.changes>0});});
app.delete('/api/admin/coupons/:id',requireAdmin,(req,res)=>{const r=db.prepare('DELETE FROM coupons WHERE id=?').run(Number(req.params.id));res.json({ok:r.changes>0});});

app.get('/api/admin/stats',requireAdmin,(req,res)=>{res.json({customers:db.prepare('SELECT COUNT(*) c FROM users WHERE role="customer"').get().c,products:db.prepare('SELECT COUNT(*) c FROM products WHERE active=1').get().c,orders:db.prepare('SELECT COUNT(*) c FROM orders').get().c,points:db.prepare('SELECT COALESCE(SUM(points),0) s FROM users WHERE role="customer"').get().s});});

app.get('/api/health',(req,res)=>res.json({ok:true,service:'points-store-v28',database:'sqlite'}));
app.use(express.static(path.join(__dirname,'public')));
app.get('/{*splat}',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
const HOST=process.env.HOST||'0.0.0.0';
const server=app.listen(PORT,HOST,()=>console.log(`Points Store V28 running on http://${HOST}:${PORT}`));
server.on('error',(err)=>{console.error('SERVER_START_ERROR',err);process.exit(1);});
