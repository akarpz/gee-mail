/*just run make to compile then ./geemail to run */
//----CryptoPPLib----
#include <crypto++/sha.h>
#include <crypto++/hex.h>
#include <crypto++/cryptlib.h>
#include <crypto++/salsa.h>
#include <crypto++/osrng.h>
//----CppStdLib----
#include <iostream>
#include <string>
#include <time.h>
#include <sstream>
#include <vector>
#include <bitset>
//----Sqlite3Lib----
#include <stdio.h>
#include <sqlite3.h>
#include "sqlite3pp/headeronly_src/sqlite3pp.h"

using namespace std;




string txt2binary(string str){
    vector<string> tmp;
    int asciiVal;
    string binaryTmp, bstring;

    for(int i = 0; i < str.size(); i++){
      asciiVal = str[i];
      binaryTmp = bitset<8>(asciiVal).to_string();
      tmp.push_back(binaryTmp);
      bstring += tmp.at(i);
    }//creates large vector of binary char(represented as strings)

    return bstring;
}// takes in plain text and converts it to hex




string binary2hex(string str){

  vector<string> tmp;
  string hstring;

  for(int i = 0; i < str.size()-1; i += 4){
    tmp.push_back(str.substr(i, 4));
  }//grabs half byte to get hex value

  for(int i = 0; i < tmp.size(); i++){
    bitset<4> set(tmp.at(i));
    stringstream ss;
    ss << hex << set.to_ulong();
    hstring += ss.str();
  }

  return hstring;
}// converts binary to hex




std::string sha256Hash(string pass){

  CryptoPP::SHA256 hash;
  byte digest[ CryptoPP::SHA256::DIGESTSIZE ];
  pass = binary2hex(txt2binary(pass));
  hash.CalculateDigest(digest, (const byte *) pass.c_str() , pass.length() );

  CryptoPP::HexEncoder encoder;
  std::string output;
  encoder.Attach( new CryptoPP::StringSink( output ) );
  encoder.Put( digest, sizeof(digest) );
  encoder.MessageEnd();

  return output;
}//generates key with sha256





string streamCipher(string plaintextStr, string ciphertextStr) {
  
  CryptoPP::AutoSeededRandomPool prng;
  
  string hashedCipherTxt = sha256Hash(ciphertextStr);

	//~Key and IV Generation/Initialization======================================
	/////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////
	char const *hashedBytes = hashedCipherTxt.c_str();
  byte hashedKey[32] = { 0 };
  byte setIv[8] = { 0 };
  
  memcpy(hashedKey, (void *)hashedBytes, 32);
  //memcpy(setIv, ((void *)((hashedBytes) * 32)), 8);

	byte *plaintextBytes = (byte *) plaintextStr.c_str();
	byte *ciphertextBytes = new byte[plaintextStr.length()];

	//~Encryption================================================================
	/////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////
	CryptoPP::Salsa20::Encryption salsa;	
	salsa.SetKeyWithIV(hashedKey, 32, setIv);
	salsa.ProcessData(ciphertextBytes, plaintextBytes, plaintextStr.length());
	ciphertextStr.assign((char *) ciphertextBytes);

	//Reset plaintext (for sanity again)
	plaintextStr.assign("");

	//Reset Key & IV
	//!!! THIS IS IMPORTANT: If you do not reset the stream cipher the data will
		//be encrypted again with a different part of the streaming key
		//Resetting the key & IV ensure that the same key is used, and we decrypt
	/////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////
	salsa.SetKeyWithIV(hashedKey, 32, setIv);
	
	return ciphertextStr;
}




std::string generateSalt(){

    stringstream ss;
    unsigned int randval;
    FILE *f;

    f = fopen("/dev/urandom", "r");
    fread(&randval, sizeof(randval), 1, f);
    fclose(f);

    ss << randval;

  return ss.str();

}//completely randomness from urandom this could be used for nonces




static int callback(void *NotUsed, int argc, char **argv, char **azColName){
    int i;
    for(i=0; i<argc; i++){
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}//requirement for sqlite connection (andy code)




string quotesql( const string& s ) {
    return string("'") + s + string("'");
}// helper method for sqlite3 calls




void userRegister(string newUser, string newPass){

    string salt, hashpass;
    salt = generateSalt();//generates a random salt for user
    int stretch = 10; //this can be increases later

    sqlite3* db;
    char *zErrMsg = 0;
    int rc;

    rc = sqlite3_open("gm.db", &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    for(int i = 0; i < stretch; i++){
    hashpass = sha256Hash(newPass + salt);
    newPass = hashpass; // hashes password for db
    }// salt and streches password

    std::string sql = "INSERT INTO USER (username, pass, salt) VALUES (" + quotesql(newUser) +","
    + quotesql(hashpass) + ", "+ quotesql(salt) + ");"; //sql command to be run

    rc = sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }else{
      fprintf(stdout, "Table insert successful\n");
    }
    sqlite3_close(db);
}// registers user to db




int program(string usr, string pass) {
    
    sqlite3pp::database db("gm.db");
    
    string numOfMessages,t;
    
    string counter = "select count(*) from MESSAGE where receiver = " + quotesql(usr) + ";";
    
    sqlite3pp::query qry4(db, counter.c_str()); //creates query object
    
    for (sqlite3pp::query::iterator i = qry4.begin(); i != qry4.end(); ++i) {
      for (int j = 0; j < qry4.column_count(); ++j) {
        numOfMessages = (*i).get<char const*>(j);
      }//for
    }//iterator
        

    cout << "Loggins uccessful" << endl;
    cout << "Welcome Back, " << usr <<" you have "<< numOfMessages<< " messages" << endl << "Your Current Messages: " <<  endl;
    string get_messages = "select id, sender, timestamp from MESSAGE where receiver = " + quotesql(usr) + ";";

    sqlite3pp::query qry3(db, get_messages.c_str()); //creates query object
    
    
    for (sqlite3pp::query::iterator i = qry3.begin(); i != qry3.end(); ++i) {
      int id;
      char const* sender, *timestamp;
      std::tie(id, sender, timestamp) =
      (*i).get_columns<int, char const*, char const*>(0, 1, 2);
      cout << "id: " << id << "\t"<< "sender: " << sender << "\t" << "timestamp: " << timestamp << endl;
    }
    
    while(1 == 1) {
      string input, recipient, message, sharedSecret, get_encrypted, messageSelect;
      cout << "Type w to write a message, r to read, x to signout, or Q to quit: " << endl;
      cin >> input;
      
      if (input == "w") {
        
        string userlist = "select username from USER;";
        sqlite3pp::query qry5(db, userlist.c_str()); //creates query object
    
        cout << "Pick a recipeint from user list: " << endl;
         for (sqlite3pp::query::iterator i = qry5.begin(); i != qry5.end(); ++i) {
          for (int j = 0; j < qry5.column_count(); ++j) {
            cout << (*i).get<char const*>(j) << endl;
          }//for
        }//iterator
        
        cin >> recipient;
        
        cin.ignore (std::numeric_limits<std::streamsize>::max(), '\n');
        cout << "Write your message here: " << endl;
        getline(std::cin , message);
        
        cout << "Input a shared secret that you will give to the other user: " << endl;
        cin >> sharedSecret;
        
        sqlite3* db;
        char *zErrMsg = 0;
        int rc;

        rc = sqlite3_open("gm.db", &db);
        if( rc ){
          fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
          sqlite3_close(db);
          exit(0);
        }
        
        string hashedCipher = sha256Hash(sharedSecret);
        
        time_t rawtime;
        time (&rawtime);
    
        string sql = "INSERT INTO MESSAGE (pass, sender, receiver, mess, timestamp) VALUES (" + quotesql(hashedCipher) +","
        + quotesql(usr) + ", "+ quotesql(recipient) + ", " + quotesql(streamCipher(message, hashedCipher)) + ", " + quotesql(ctime(&rawtime)) + ");";
    
        rc = sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg);
        if( rc != SQLITE_OK ){
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
          sqlite3_free(zErrMsg);
        }else{
          fprintf(stdout, "Message sent!\n");
        }
        sqlite3_close(db);
      }//end write
      
      else if (input == "r"){
        cout << "Which message would you like to read:" << endl;
        cin >> messageSelect;
        cout << "what is the your shared passphrase:" << endl;
        cin >> sharedSecret;
        
        std::string get_encrypted = "select mess from MESSAGE where id = " + quotesql(messageSelect) + ";";

        sqlite3pp::query qry3(db, get_encrypted.c_str()); //creates query object
        for (sqlite3pp::query::iterator i = qry3.begin(); i != qry3.end(); ++i) {
          for (int j = 0; j < qry3.column_count(); ++j) {
            cout << streamCipher((*i).get<char const*>(j), sha256Hash(sharedSecret)) << endl;//should display decryptedtxt
          }
        }
        
      }//read end 
      
      else if(input == "x"){
      //TODO: restart the program
      break;
      }//end 
      
      else if (input == "Q") {
        cout << "Exiting... Have a good day" << endl;
        exit(0);
      }
    }
}//lets users read and write messages to the db




void userloggin() {

  string usr, attemptedPass;

  int logginAttempts, attemptsLeft, *incrementor, *decrementor;
  logginAttempts = 0;
  attemptsLeft = 2;
  incrementor = &logginAttempts;
  decrementor = &attemptsLeft;
  
  int stretch;
  string hashpass,get_salt,get_sha256Pass,userSalt,DBpass,get_messages;
  stretch = 10; //this can be increases later

  while(logginAttempts < 3){
    
    cout << "Username: " << endl;
    cin >> usr;
    cout << "Password: " << endl;
    cin >> attemptedPass;

    sqlite3pp::database db("gm.db");

    get_salt = "select salt from USER where USER.username =" + quotesql(usr) + ";";

    sqlite3pp::query qry(db, get_salt.c_str());//creates query object

    for (sqlite3pp::query::iterator i = qry.begin(); i != qry.end(); ++i) {
      for (int j = 0; j < qry.column_count(); ++j) {
        userSalt = (*i).get<char const*>(j);
      }//for
    }//interator

    qry.reset();//resets qry obj for next query (not sure its needed)

    for(int i = 0; i < stretch; i++){
    hashpass = sha256Hash(attemptedPass + userSalt);
    attemptedPass = hashpass;
  }// returns attempted pass hash

    std::string get_sha256Pass = "select pass from USER where USER.username =" + quotesql(usr) + ";";

    sqlite3pp::query qry2(db, get_sha256Pass.c_str()); //creates query object

    for (sqlite3pp::query::iterator i = qry2.begin(); i != qry2.end(); ++i) {
      for (int j = 0; j < qry2.column_count(); ++j) {
        DBpass = (*i).get<char const*>(j);
      }//for
    }//interator

    if(attemptedPass.compare(DBpass) == 0) {
      //sqlite3_close(&db);
      program(usr, attemptedPass);
    }
    else {
      cout << "Nope try again you have " << attemptsLeft << " trys left" << endl;
      ++*incrementor;
      --*decrementor;
    }
  }
  cout << "Stop hacking, nerd" << endl;
  exit(0);
}// lets users loggin to their accounts




int main() {

    // string plainTxt = "aliqua occaecat turkey quis pancetta non. Nulla officia magna proident tri-tip.";
    // cout << "PLAIN TEXT: " << plainTxt << endl;
    // string encrypted = streamCipher(plainTxt, sha256Hash("curtis"));
    // cout << "ENCRYPTED TEXT " << encrypted << endl;
    // cout << "DECRYPTED TEXT: " << streamCipher(encrypted, sha256Hash("curtis")) << endl;

while(1==1){
    string command;
    string user;
    string pass;
    
    cout << "Welcome to Geemail. Please enter 's' to sign in or 'r' to register: " << endl;
    cin >> command;
    
    if(command == "s") {
      userloggin();
    }
    else if(command == "r") {
      cout << "Username: " << endl;
      cin >> user;
      cout << "Password: " << endl;
      cin >> pass;
      userRegister(user, pass);
    }
    else {
      cout << "Invalid Input. Exiting...";
      exit(0);
    }
}
  //userRegister("Jon","pass");
  //userRegister("Test","passwrd");

}
