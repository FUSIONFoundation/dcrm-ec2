// Copyright 2019 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm

import(
	"strings"
	"errors"
	"runtime"
	"path/filepath"
	"os"
	"os/user"
	"github.com/fusion/go-fusion/ethdb"
	"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/log"
)


func GetDbDir() string {
    if datadir != "" {
	return datadir+"/dcrmdb"
    }

    ss := []string{"dir",cur_enode}
    dir = strings.Join(ss,"-")
    return dir
}

func DefaultDataDir() string {
	home := homeDir()
	if home != "" {
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Fusion")
		} else if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Roaming", "Fusion")
		} else {
			return filepath.Join(home, ".fusion")
		}
	}
	// As we cannot guess a stable location, return empty and handle later
	return ""
}

func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}

//for lockout info 
func GetDbDirForLockoutInfo() string {

    if datadir != "" {
	return datadir+"/lockoutinfo"
    }

    s := DefaultDataDir()
    log.Debug("==========GetDbDirForLockoutInfo,","datadir",s,"","===========")
    s += "/lockoutinfo"
    return s
}

//for write dcrmaddr 
func GetDbDirForWriteDcrmAddr() string {

    if datadir != "" {
	return datadir+"/dcrmaddrs"
    }

    s := DefaultDataDir()
    log.Debug("==========GetDbDirForWriteDcrmAddr,","datadir",s,"","===========")
    s += "/dcrmaddrs"
    return s
}

//for node info save
func GetDbDirForNodeInfoSave() string {

    if datadir != "" {
	return datadir+"/nodeinfo"
    }

    s := DefaultDataDir()
    log.Debug("==========GetDbDirForNodeInfoSave,","datadir",s,"","===========")
    s += "/nodeinfo"
    return s
}

//for lockin
func GetDbDirForLockin() string {
    if datadir != "" {
	return datadir+"/hashkeydb"
    }

    ss := []string{"dir",cur_enode}
    dir = strings.Join(ss,"-")
    dir += "-"
    dir += "hashkeydb"
    return dir
}

func SetDatadir (data string) {
	datadir = data
}

func GetLockoutInfoFromLocalDB(hashkey string) (string,error) {
    if hashkey == "" {
	return "",errors.New("param error get lockout info from local db by hashkey.")
    }
    
    lock5.Lock()
    path := GetDbDirForLockoutInfo()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============GetLockoutInfoFromLocalDB,create db fail.============")
	lock5.Unlock()
	return "",errors.New("create db fail.")
    }
    
    value,has:= db.Get([]byte(hashkey))
    if string(value) != "" && has == nil {
	db.Close()
	lock5.Unlock()
	return string(value),nil
    }

    db.Close()
    lock5.Unlock()
    return "",nil
}

func WriteLockoutInfoToLocalDB(hashkey string,value string) (bool,error) {
    if !IsInGroup() {
	return false,errors.New("it is not in group.")
    }

    if hashkey == "" || value == "" {
	return false,errors.New("param error in write lockout info to local db.")
    }

    lock5.Lock()
    path := GetDbDirForLockoutInfo()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============WriteLockoutInfoToLocalDB,create db fail.============")
	lock5.Unlock()
	return false,errors.New("create db fail.")
    }
    
    db.Put([]byte(hashkey),[]byte(value))
    db.Close()
    lock5.Unlock()
    return true,nil
}

//========
func ReadDcrmAddrFromLocalDBByIndex(fusion string,cointype string,index int) (string,error) {

    if fusion == "" || cointype == "" || index < 0 {
	return "",errors.New("param error.")
    }

    lock4.Lock()
    path := GetDbDirForWriteDcrmAddr()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============ReadDcrmAddrFromLocalDBByIndex,create db fail.============")
	lock4.Unlock()
	return "",errors.New("create db fail.")
    }
    
    hash := crypto.Keccak256Hash([]byte(strings.ToLower(fusion) + ":" + strings.ToLower(cointype))).Hex()
    value,has:= db.Get([]byte(hash))
    if string(value) != "" && has == nil {
	    v := strings.Split(string(value),":")
	    if len(v) < (index + 1) {
		db.Close()
		lock4.Unlock()
		return "",errors.New("has not dcrmaddr in local DB.")
	    }

	    db.Close()
	    lock4.Unlock()
	    return v[index],nil
    }
	db.Close()
	lock4.Unlock()
	return "",errors.New("has not dcrmaddr in local DB.")
}

func IsFusionAccountExsitDcrmAddr(fusion string,cointype string,dcrmaddr string) (bool,string,error) {
    if fusion == "" || cointype == "" {
	return false,"",errors.New("param error")
    }
    
    lock4.Lock()
    path := GetDbDirForWriteDcrmAddr()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============IsFusionAccountExsitDcrmAddr,create db fail.============")
	lock4.Unlock()
	return false,"",errors.New("create db fail.")
    }
    
    hash := crypto.Keccak256Hash([]byte(strings.ToLower(fusion) + ":" + strings.ToLower(cointype))).Hex()
    if dcrmaddr == "" {
	has,_ := db.Has([]byte(hash))
	if has == true {
		log.Debug("========IsFusionAccountExsitDcrmAddr,has req dcrmaddr.==============")
		value,_:= db.Get([]byte(hash))
		v := strings.Split(string(value),":")
		db.Close()
		lock4.Unlock()
		return true,string(v[0]),nil
	}

	log.Debug("========IsFusionAccountExsitDcrmAddr,has not req dcrmaddr.==============")
	db.Close()
	lock4.Unlock()
	return false,"",nil
    }
    
    value,has:= db.Get([]byte(hash))
    if has == nil && string(value) != "" {
	v := strings.Split(string(value),":")
	if len(v) < 1 {
	    log.Debug("========IsFusionAccountExsitDcrmAddr,data error.==============")
	    db.Close()
	    lock4.Unlock()
	    return false,"",errors.New("data error.")
	}

	for _,item := range v {
	    if strings.EqualFold(item,dcrmaddr) {
		log.Debug("========IsFusionAccountExsitDcrmAddr,success get dcrmaddr.==============")
		db.Close()
		lock4.Unlock()
		return true,dcrmaddr,nil
	    }
	}
    }
   
    log.Debug("========IsFusionAccountExsitDcrmAddr,fail get dcrmaddr.==============")
    db.Close()
    lock4.Unlock()
    return false,"",nil

}

func WriteDcrmAddrToLocalDB(fusion string,cointype string,dcrmaddr string) (bool,error) {
    if !IsInGroup() {
	return false,errors.New("it is not in group.")
    }

    if fusion == "" || cointype == "" || dcrmaddr == "" {
	return false,errors.New("param error in write dcrmaddr to local db.")
    }

    lock4.Lock()
    path := GetDbDirForWriteDcrmAddr()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============WriteDcrmAddrToLocalDB,create db fail.============")
	lock4.Unlock()
	return false,errors.New("create db fail.")
    }
    
    hash := crypto.Keccak256Hash([]byte(strings.ToLower(fusion) + ":" + strings.ToLower(cointype))).Hex()
    has,_ := db.Has([]byte(hash))
    if has != true {
	db.Put([]byte(hash),[]byte(dcrmaddr))
	db.Close()
	lock4.Unlock()
	return true,nil
    }
    
    value,_:= db.Get([]byte(hash))
    v := string(value)
    v += ":"
    v += dcrmaddr
    db.Put([]byte(hash),[]byte(v))
    db.Close()
    lock4.Unlock()
    return true,nil
}
//========

func ReadNodeInfoFromLocalDB(nodeinfo string) (string,error) {

    if nodeinfo == "" {
	return "",errors.New("param error in read nodeinfo from local db.")
    }

    lock3.Lock()
    path := GetDbDirForNodeInfoSave()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============ReadNodeInfoFromLocalDB,create db fail.============")
	lock3.Unlock()
	return "",errors.New("create db fail.")
    }
    
    value,has:= db.Get([]byte(nodeinfo))
    if string(value) != "" && has == nil {
	    db.Close()
	    lock3.Unlock()
	    return string(value),nil
    }
	db.Close()
	lock3.Unlock()
	return "",errors.New("has not nodeinfo in local DB.")
}

func IsNodeInfoExsitInLocalDB(nodeinfo string) (bool,error) {
    if nodeinfo == "" {
	return false,errors.New("param error in check local db by nodeinfo.")
    }
    
    lock3.Lock()
    path := GetDbDirForNodeInfoSave()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============IsNodeInfoExsitInLocalDB,create db fail.============")
	lock3.Unlock()
	return false,errors.New("create db fail.")
    }
    
    has,_ := db.Has([]byte(nodeinfo))
    if has == true {
	    db.Close()
	    lock3.Unlock()
	    return true,nil
    }

    db.Close()
    lock3.Unlock()
    return false,nil
}

func WriteNodeInfoToLocalDB(nodeinfo string,value string) (bool,error) {
    if !IsInGroup() {
	return false,errors.New("it is not in group.")
    }

    if nodeinfo == "" || value == "" {
	return false,errors.New("param error in write nodeinfo to local db.")
    }

    lock3.Lock()
    path := GetDbDirForNodeInfoSave()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============WriteNodeInfoToLocalDB,create db fail.============")
	lock3.Unlock()
	return false,errors.New("create db fail.")
    }
    
    db.Put([]byte(nodeinfo),[]byte(value))
    db.Close()
    lock3.Unlock()
    return true,nil
}

func IsHashkeyExsitInLocalDB(hashkey string) (bool,error) {
    if hashkey == "" {
	return false,errors.New("param error in check local db by hashkey.")
    }
    
    lock2.Lock()
    path := GetDbDirForLockin()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============IsHashkeyExsitInLocalDB,create db fail.============")
	lock2.Unlock()
	return false,errors.New("create db fail.")
    }
    
    has,_ := db.Has([]byte(hashkey))
    if has == true {
	    db.Close()
	    lock2.Unlock()
	    return true,nil
    }

	db.Close()
	lock2.Unlock()
	return false,nil
}

func WriteHashkeyToLocalDB(hashkey string,value string) (bool,error) {
    if !IsInGroup() {
	return false,errors.New("it is not in group.")
    }

    if hashkey == "" || value == "" {
	return false,errors.New("param error in write hashkey to local db.")
    }

    lock2.Lock()
    path := GetDbDirForLockin()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============WriteHashkeyToLocalDB,create db fail.============")
	lock2.Unlock()
	return false,errors.New("create db fail.")
    }
    
    db.Put([]byte(hashkey),[]byte(value))
    db.Close()
    lock2.Unlock()
    return true,nil
}

