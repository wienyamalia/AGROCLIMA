const express = require ('express');
const cors = require ('cors');
const cookieParser = require ('cookie-parser');
const bodyParser = require ('body-parser');
const bcrypt = require ('bcryptjs');
const dotenv = require ('dotenv');
const { Sequelize} = require('sequelize');
const jwt = require ('jsonwebtoken');
const multer = require ('multer');
const fs = require ('fs');
const {Storage} = require ('@google-cloud/storage');

dotenv.config();
const app = express();
const upload = multer({dest: 'uploads/'});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server Running at port ${PORT}`)
});

//connect to database
const db = new Sequelize('agro_clima', 'root', '123', {
    host: '34.28.108.156', //34.28.108.156
    dialect: 'mysql'
});
try {
    db.authenticate();
    console.log('Database Connected...')
} catch (error) {
    console.log(error);    
};

//connect to cloud storage
const storage = new Storage({
    keyFilename: 'capstonec23-ps118-bbac9b349534.json', // Ganti dengan nama file kunci GCP Anda
    projectId: 'capstonec23-ps118.appspot.com', // Ganti dengan ID proyek Google Cloud Anda
});

//using bucket cloud storage
const bucketName = 'capstonec23-ps118.appspot.com'; // Ganti dengan nama bucket Google Cloud Storage Anda
const bucket = storage.bucket(bucketName);


app.use(cors({ credentials: true, origin: '0.0.0.0'}));
app.use(express.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(cookieParser());

app.use(express());
//initialitation table in database

const {DataTypes} = Sequelize;
// table users for logim-register pages
const Users = db.define('users', {
    name: DataTypes.STRING,
    email: DataTypes.STRING,
    no_hp: DataTypes.STRING,
    password: DataTypes.STRING,
    refresh_token: DataTypes.TEXT
}, {
    freezeTableName: true
});

//table for recommendation pages
const Rec = db.define('recommendation', {
    N: DataTypes.STRING,
    P: DataTypes.STRING,
    K: DataTypes.STRING,
    temperature: DataTypes.STRING,
    humidity: DataTypes.STRING,
    ph: DataTypes.STRING,
    rainfall: DataTypes.STRING
}, {
    freezeTableName: true
});

//table for product pages
const Product = db.define('products', {
    name: DataTypes.STRING,
    price: DataTypes.STRING,
    description: DataTypes.STRING,
    photo: DataTypes.STRING,
}, {
    freezeTableName: true
});

//table for article pages
const Article = db.define('articles', {
    title: DataTypes.STRING,
    description: DataTypes.STRING,
    photo: DataTypes.STRING,
}, {
    freezeTableName: true
});

//create new table
// (async() => {
//     await db.sync();
// })();

//LOGIN-REGISTER PAGES
//verify token middleware
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) return res.sendStatus(403);
        req.email = decoded.email;
        next();
    })
}

//GET all data users
app.get('/login/user', verifyToken, async (req, res) => {
    try {
        const users = await Users.findAll({
            attributes: ['id', 'name', 'email', 'no_hp']
        });
        res.json(users);
    } catch (error) {
        console.log(error);
    }
});

//GET users by Id
app.get('/login/user/:id', verifyToken, async (req, res) => {
    try {
        const users = await Users.findOne({
            where: {
                id: req.params.id
            },
            attributes: ['id', 'name', 'email', 'no_hp']
        });
        res.json(users);
    } catch (error) {
        console.log(error);
    }
});

//Register new user
app.post('/register', async(req, res) => {
    const {name, email, no_hp, password, confirmPassword} = req.body;       

    //check if password match
    if (password !== confirmPassword) {
        return res.status(400).json({msg: "Password do not match"});
    };

    //chek password length
    if (password.length < 6) {
        return res.status(400).json({msg: "Password must be at least 6 characters"});
    };    

    try {
        //generate salt for password hashing
        const salt = await bcrypt.genSalt();

        // hash the password
        const hashedPassword = await bcrypt.hash(password, salt);

        //save password on database
        await Users.create({
            name: name,
            email: email,
            no_hp: no_hp,
            password: hashedPassword
        });
        res.json({ status: true, msg: "Registered successfully", data: { name, email, no_hp } });
    } catch (error) {
        console.log(error);
        res.status(500).json({status: false, msg: 'Try again'});
    }
});

//Login User
app.post('/login', async(req, res) => {
    try {
        const user = await Users.findOne({
            where: {
                email: req.body.email
            }
        });
        //check if user exist
        if(!user) {
            return res.status(404).json({msg: "Email not Found!"})
        }
        const match = await bcrypt.compare(req.body.password, user.password);
        if(!match) return res.status(400).json({msg: "Wrong Password"});        
        
        const userId = user.id;
        const name = user.name;
        const email = user.email;
        const no_hp = user.no_hp;
        const accessToken = jwt.sign({userId, name, email, no_hp}, process.env.ACCESS_TOKEN_SECRET, {
            expiresIn: '1d'
        });
        const refreshToken = jwt.sign({userId, name, email, no_hp}, process.env.REFRESH_TOKEN_SECRET, {
            expiresIn: '7d'
        });
        await Users.update({refresh_token: refreshToken}, {
            where: {
                id: userId
            }
        });
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000,
        });        
        res.json({ status: true, msg: "Login Success", data: { name, email, no_hp },accessToken});
    } catch (error) {
        res.status(404).json({msg: "Login Failed!"});   
        console.log(error);
    }
});

//get new token
app.get('/login/token', async(req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if(!refreshToken) return res.sendStatus(401);
        const user = await Users.findAll({
            where:{
                refresh_token: refreshToken
            }
        });
        if(!user[0]) return res.sendStatus(403);
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
            if(err) return res.sendStatus(403);
            const userId = user[0].id;
            const name = user[0].name;
            const email = user[0].email;
            const accessToken = jwt.sign({userId, name, email}, process.env.ACCESS_TOKEN_SECRET,{
                expiresIn: "90s"
            });
            res.json({ accessToken });
        })
    } catch (error) {
        console.log(error);
    }
});

//RECOMMENDATION PAGES
//get all of data Recommendation
app.get('/Recommendation/data', async(req, res) => {
    try {
        const rec = await Rec.findAll({
            attributes: ['id', 'N', 'P', 'K', 'temperature', 'humidity', 'ph', 'rainfall'],
        });
        res.json(rec);
    } catch (error) {
        console.log(error);
    }
});

//get data Recommendation by Id
app.get('/Recommendation/data/:id', async(req, res) => {
    try {
        const rec = await Rec.findOne({
            attributes: ['id', 'N', 'P', 'K', 'temperature', 'humidity', 'ph', 'rainfall'],
            where: {
                id: req.params.id
            }
        });
        res.json(rec);
    } catch (error) {
        console.log(error);
    }
});

//create new data recommendation
app.post('/Recommendation/new', async(req, res) => {
    const {N, P, K, temperature, humidity, ph, rainfall} = req.body;
    //create data into db
    try {
        await Rec.create({
            N: N,
            P: P,
            K: K,
            temperature: temperature,
            humidity: humidity,
            ph: ph,
            rainfall: rainfall
        });
        res.json({msg: "Created Success"});
    } catch (error) {
        console.log(error);
    }
});

//delete data recommendation by id
app.delete('/Recommendation/data/:id', async(req, res) => {
    const id = req.params.id;
    //delete from db
    try {
        await Rec.destroy({
            where: {id: id},
        });
        res.json({msg: 'Data was deleted'})
    } catch (error) {
        console.log(error);        
    }
});


//PRODUCT PAGES
//get all product
app.get('/Product', async(req, res) => {
    try {
        const rec = await Product.findAll({
            attributes: ['id', 'name', 'price', 'description', 'photo'],
        });
        res.json(rec);
    } catch (error) {
        console.log(error);
    }
});

//get all product by Id
app.get('/Product/:id', async(req, res) => {
    try {
        const rec = await Product.findOne({
            attributes: ['id', 'name', 'price', 'description', 'photo'],
            where: {
                id: req.params.id
            }
        });
        res.json(rec);
    } catch (error) {
        console.log(error);
    }
});

//added new product
app.post('/Product', upload.single('photo'), (req, res) => {
    const {name, price, description} = req.body;
    const photoPath = req.file.path;

    //upload photo in cloud storage
    const bucket = storage.bucket(bucketName);
    const photoFileName = `${Date.now()}_${req.file.originalname}`;
    const photoFile = bucket.file(photoFileName);
    const photoStream = photoFile.createWriteStream({
        metadata: {
            contentType: req.file.mimetype
        },
    });

    photoStream.on('error', (err) => {
        console.error('Error uploading photo', err);
        res.status(500).json({msg: 'Failed to upload photo'});
    });

    photoStream.on('finish', async() => {
        const photoUrl = `https://storage.googleapis.com/${bucketName}/${photoFileName}`;

        //saved to database
        try {
            await Product.create({
                name: name,
                price: price,
                description: description,
                photo: photoUrl, 
            });
            res.json({msg: "Created Success"});
        } catch (error) {
            console.log(error);
        };
    });

    //uploading photo process
    fs.createReadStream(photoPath).pipe(photoStream);
});

//delete product by id
app.delete('/Product/:id', async(req, res) => {
    try {
        await Product.destroy({
            where: {
                id: req.params.id
            }
        });
        res.json({msg: `Product ${id} was deleted`});
    } catch (error) {
        console.log(error);
    };
});

//ARTICLE PAGES
//get all article
app.get('/Article', async(req, res) => {
    try {
        const rec = await Article.findAll({
            attributes: ['id', 'title', 'description', 'photo'],
        });
        res.json(rec);
    } catch (error) {
        console.log(error);
    }
});

//get all article by Id
app.get('/Article/:id', async(req, res) => {
    try {
        const rec = await Article.findOne({
            attributes: ['id', 'title', 'description', 'photo'],
            where: {
                id: req.params.id
            }
        });
        res.json(rec);
    } catch (error) {
        console.log(error);
    }
});

//added new article
app.post('/Article', upload.single('photo'), (req, res) => {
    const {title, description} = req.body;
    const photoPath = req.file.path;

    //upload photo in cloud storage
    const bucket = storage.bucket(bucketName);
    const photoFileName = `${Date.now()}_${req.file.originalname}`;
    const photoFile = bucket.file(photoFileName);
    const photoStream = photoFile.createWriteStream({
        metadata: {
            contentType: req.file.mimetype
        },
    });

    photoStream.on('error', (err) => {
        console.error('Error uploading photo', err);
        res.status(500).json({msg: 'Failed to upload photo'});
    });

    photoStream.on('finish', async() => {
        const photoUrl = `https://storage.googleapis.com/${bucketName}/${photoFileName}`;

        //saved to database
        try {
            await Article.create({
                title: title,
                description: description,
                photo: photoUrl, 
            });
            res.json({msg: "Created Success"});
        } catch (error) {
            console.log(error);
        };
    });

    //uploading photo process
    fs.createReadStream(photoPath).pipe(photoStream);
});

//delete product by id
app.delete('/Article/:id', async(req, res) => {
    try {
        await Article.destroy({
            where: {
                id: req.params.id
            }
        });
        res.json({msg: 'Product was deleted'});
    } catch (error) {
        console.log(error);
    };
});

