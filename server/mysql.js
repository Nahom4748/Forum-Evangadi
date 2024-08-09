// CREATE TABLE users(
// 	userid INT(20) NOT NULL AUTO_INCREMENT,
// 	username VARCHAR(20) NOT NULL,
//     firstname VARCHAR(20) NOT NULL,
//     lastname VARCHAR(20) NOT NULL,
//     email VARCHAR(40) NOT NULL,
//     password VARCHAR(100) NOT NULL,
//     PRIMARY KEY (userid)
// );

// CREATE TABLE questions(
// 	id INT(20) NOT NULL AUTO_INCREMENT,
// 	questionid VARCHAR(100) NOT NULL UNIQUE,
//     userid INT(20) NOT NULL,
//     title VARCHAR(50) NOT NULL,
//     description VARCHAR(200) NOT NULL,
//     tag VARCHAR(20),
//     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//     PRIMARY KEY (id,userid),
//     FOREIGN KEY (userid) REFERENCES users(userid)
// );

// CREATE TABLE answers(
// 	answerid INT(20) NOT NULL AUTO_INCREMENT,
//     userid INT(20) NOT NULL,
//     username VARCHAR(20) NOT NULL,
//     questionid VARCHAR(100) NOT NULL,
//     answer VARCHAR(200) NOT NULL,
//     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//     PRIMARY KEY (answerid),
//     FOREIGN KEY (questionid) REFERENCES questions(questionid),
//     FOREIGN KEY (username) REFERENCES users(username),
//     FOREIGN KEY (userid) REFERENCES users(userid)

// );
