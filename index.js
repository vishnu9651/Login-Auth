require("./config/db");

const app=require("express")()
const port = process.env.PORT || 8080;

//cors
const cors=require("cors");
app.use(cors());



const UserRouter=require("./api/User")



//for accepting post from data
const bodyParser=require("express").json;
app.use(bodyParser());


app.get('/', function(req, res) {
    res.send('Hello world vishnu')
})

app.use("/user",UserRouter)


app.listen(port,()=>{
    console.log(`server running on port ${port}`);
})
