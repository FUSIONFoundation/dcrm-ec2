// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm

import (
	"math/big"
	"github.com/fusion/go-fusion/crypto/secp256k1"
	"fmt"
	"errors"
	"strings"
	"github.com/fusion/go-fusion/common/math"
	"github.com/fusion/go-fusion/crypto/dcrm/ec2/paillier"
	"github.com/fusion/go-fusion/crypto/dcrm/ec2/commit"
	"github.com/fusion/go-fusion/crypto/dcrm/ec2/vss"
	p2pdcrm "github.com/fusion/go-fusion/p2p/dcrm"
	"github.com/fusion/go-fusion/p2p/discover"
	"os"
	"github.com/fusion/go-fusion/common"
	"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/ethdb"
	"github.com/fusion/go-fusion/core/types"
	//"github.com/fusion/go-fusion/core/vm"
	//"github.com/fusion/go-fusion/core"
	"sync"
	"encoding/json"
	"strconv"
	"bytes"
	"context"
	"time"
	"github.com/fusion/go-fusion/rpc"
	"github.com/fusion/go-fusion/common/hexutil"
	//"github.com/fusion/go-fusion/rlp"
	"github.com/fusion/go-fusion/ethclient"
	"encoding/hex"
	"github.com/fusion/go-fusion/log"
	"github.com/syndtr/goleveldb/leveldb"
	"runtime"
	"path/filepath"
	"os/user"
	"os/exec"
	"github.com/fusion/go-fusion/common/math/random"
	"github.com/fusion/go-fusion/crypto/sha3"
	"sort"
)
////////////

var (
    tmp2 string
    sep = "dcrmparm"
    sep2 = "dcrmmsg"
    sep3 = "caihaijun"
    sep4 = "dcrmsep4"
    sep5 = "dcrmsep5"
    sep6 = "dcrmsep6"
    sep8 = "dcrmsep8" //valatetx
    sep9 = "dcrmsep9" //valatetx
    sep10 = "dcrmsep10" //valatetx
    sep11 = "dcrmsep11"
    sep12 = "dcrmsep12"
    msgtypesep = "caihaijundcrm"
    lock sync.Mutex
    
    FSN      Backend

    dir string//dir,_= ioutil.TempDir("", "dcrmkey")
    NodeCnt = 3
    THRESHOLD = 3
    TOTALNODES = 3
    PaillierKeyLength = 2048

    CHAIN_ID       = 4 //ethereum mainnet=1 rinkeby testnet=4

    cur_enode string
    enode_cnts int 

    // 0:main net  
    //1:test net
    //2:namecoin
    bitcoin_net = 1

    //rpc-req //dcrm node
    RpcMaxWorker = 20000
    RpcMaxQueue  = 20000
    RpcReqQueue chan RpcReq 
    workers []RpcReqWorker
    //rpc-req
    
    //non dcrm node
    non_dcrm_workers []RpcReqNonDcrmWorker
    RpcMaxNonDcrmWorker = 20000
    RpcMaxNonDcrmQueue  = 20000
    RpcReqNonDcrmQueue chan RpcReq 

    datadir string
    init_times = 0

    ETH_SERVER = "http://54.183.185.30:8018"
    ch_t = 100 
	
    erc20_client *ethclient.Client
    
    //for lockin
    lock2 sync.Mutex
    
    //for node info save
    lock3 sync.Mutex
    //for write dcrmaddr 
    lock4 sync.Mutex
    //for get lockout info 
    lock5 sync.Mutex

    BTC_BLOCK_CONFIRMS int64
    BTC_DEFAULT_FEE float64
    ETH_DEFAULT_FEE *big.Int

    mergenum = 0

    //
    BLOCK_FORK_0 = "18000" //fork for dcrmsendtransaction.not to self.
    BLOCK_FORK_1 = "280000" //fork for lockin,txhash store into block.
    BLOCK_FORK_2 = "100000" //fork for lockout choose real dcrm from.

    rpcs *big.Int //add for rpc cmd prex
)

func IsCodeVersion(version string) bool {
    return false
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

func GetChannelValue(t int,obj interface{}) (string,error) {
    timeout := make(chan bool, 1)
    go func(timeout chan bool) {
	 time.Sleep(time.Duration(t)*time.Second) //1000 == 1s
	 //log.Debug("==========GetChannelValue,timeout.==============")
	 timeout <- true
     }(timeout)

     switch obj.(type) {
	 case chan interface{} :
	     //log.Debug("==========GetChannelValue,get chan interface{}==============")
	     ch := obj.(chan interface{})
	     select {
		 case v := <- ch :
		     //log.Debug("==========GetChannelValue,get RpcDcrmRes==============")
		     ret,ok := v.(RpcDcrmRes)
		     if ok == true {
			     //log.Debug("==========GetChannelValue,get RpcDcrmRes.ret.==============")
			    //return ret.ret,nil
			    if ret.ret != "" {
				return ret.ret,nil
			    } else {
				return "",ret.err
			    }
		     }
		 case <- timeout :
		     //log.Debug("==========GetChannelValue,get channel value time out.==============")
		     return "",errors.New("get rpc result time out")
	     }
	 case chan NodeWorkId:
	     ch := obj.(chan NodeWorkId)
	     select {
		 case v := <- ch :
			 return v.enode + "-" + strconv.Itoa(v.workid),nil
		 case <- timeout :
		     return "",errors.New("get other nodes's enode and workid time out")
	     }
	 case chan string:
	     ch := obj.(chan string)
	     select {
		 case v := <- ch :
			    return v,nil 
		 case <- timeout :
		     return "",errors.New("get channel value time out")
	     }
	 case chan int64:
	     ch := obj.(chan int64)
	     select {
		 case v := <- ch :
		    return strconv.Itoa(int(v)),nil 
		 case <- timeout :
		     return "",errors.New("get channel value time out")
	     }
	 case chan int:
	     ch := obj.(chan int)
	     select {
		 case v := <- ch :
		    return strconv.Itoa(v),nil 
		 case <- timeout :
		     return "",errors.New("get channel value time out")
	     }
	 case chan bool:
	     ch := obj.(chan bool)
	     select {
		 case v := <- ch :
		    if !v {
			return "false",nil
		    } else {
			return "true",nil
		    }
		 case <- timeout :
		     //log.Debug("==========GetChannelValue,get channel value time out.==============")
		     return "",errors.New("get channel value time out")
	     }
	 default:
	    return "",errors.New("unknown channel type:") 
     }

     return "",errors.New("get channel value fail.")
 }

type DcrmAddrInfo struct {
    DcrmAddr string 
    FusionAccount  string 
    CoinType string
    Balance *big.Int
}

type DcrmAddrInfoWrapper struct {
    dcrmaddrinfo [] DcrmAddrInfo
    by func(p, q * DcrmAddrInfo) bool
}

func (dw DcrmAddrInfoWrapper) Len() int {
    return len(dw.dcrmaddrinfo)
}

func (dw DcrmAddrInfoWrapper) Swap(i, j int){
    dw.dcrmaddrinfo[i], dw.dcrmaddrinfo[j] = dw.dcrmaddrinfo[j], dw.dcrmaddrinfo[i]
}

func (dw DcrmAddrInfoWrapper) Less(i, j int) bool {
    return dw.by(&dw.dcrmaddrinfo[i], &dw.dcrmaddrinfo[j])
}

func MergeDcrmBalance2(account string,from string,to string,value *big.Int,cointype string,res chan bool) {
    if strings.EqualFold(cointype,"ETH") || strings.EqualFold(cointype,"BTC") {
	    va := fmt.Sprintf("%v",value)
	    v := DcrmLockout{Txhash:"xxx",Tx:"xxx",FusionFrom:"xxx",DcrmFrom:"xxx",RealFusionFrom:account,RealDcrmFrom:from,Lockoutto:to,Value:va,Cointype:cointype}
	    retva,err := Validate_Lockout(&v)
	    if err != nil || retva == "" {
		    log.Debug("=============MergeDcrmBalance,send tx fail.==============")
		    res <-false 
		    return 
	    }
	    
	    retvas := strings.Split(retva,":")
	    if len(retvas) != 2 {
		res <-false 
		return
	    }
	    hashkey := retvas[0]
	    realdcrmfrom := retvas[1]
	    
	    vv := DcrmLockin{Tx:"xxx"+"-"+va+"-"+cointype,LockinAddr:to,Hashkey:hashkey,RealDcrmFrom:realdcrmfrom}
	    if _,err = Validate_Txhash(&vv);err != nil {
		    log.Debug("=============MergeDcrmBalance,validate fail.==============")
		res <-false 
		return
	    }

	    res <-true
	    return
	}
}

func MergeDcrmBalance(account string,from string,to string,value *big.Int,cointype string) {
    if account == "" || from == "" || to == "" || value == nil || cointype == "" {
	return
    }

    count := 0
    for {
	count++
	if count == 400 {
	    return
	}
	
	res := make(chan bool, 1)
	go MergeDcrmBalance2(account,from,to,value,cointype,res)
	ret,cherr := GetChannelValue(ch_t,res)
	if cherr != nil {
	    return	
	}

	if ret != "" {
	    mergenum++
	    return
	}
	 
	time.Sleep(time.Duration(10)*time.Second) //1000 == 1s
    }
}

func ChooseRealFusionAccountForLockout(amount string,lockoutto string,cointype string) (string,string,error) {

    var dai []DcrmAddrInfo
    
    if strings.EqualFold(cointype,"ETH") == true {

	 client, err := rpc.Dial(ETH_SERVER)
	if err != nil {
	        log.Debug("===========ChooseRealFusionAccountForLockout,rpc dial fail.==================")
		return "","",errors.New("rpc dial fail.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	lock.Lock()
	dbpath := GetDbDir()
	log.Debug("===========ChooseRealFusionAccountForLockout,","db path",dbpath,"","===============")
	db, err := leveldb.OpenFile(dbpath, nil) 
	if err != nil { 
	    log.Debug("===========ChooseRealFusionAccountForLockout,ERROR: Cannot open LevelDB.","get error info",err.Error(),"","================")
	    cancel()
	    lock.Unlock()
	    return "","",errors.New("ERROR: Cannot open LevelDB.")
	} 
    
	var b bytes.Buffer 
	b.WriteString("") 
	b.WriteByte(0) 
	b.WriteString("") 
	iter := db.NewIterator(nil, nil) 
	for iter.Next() { 
	    key := string(iter.Key())
	    value := string(iter.Value())
	    log.Debug("===========ChooseRealFusionAccountForLockout,","key",key,"","===============")

	    s := strings.Split(value,sep)
	    if len(s) != 0 {
		var m AccountListInfo
		ok := json.Unmarshal([]byte(s[0]), &m)
		if ok == nil {
		    ////
		} else {
		    dcrmaddrs := []rune(key)
		    if len(dcrmaddrs) == 42 { //ETH
			////
			_,_,err = IsFusionAccountExsitDcrmAddr(s[0],cointype,key) 
			if err == nil {
			    var result hexutil.Big
			    //blockNumber := nil
			    err = client.CallContext(ctx, &result, "eth_getBalance", key, "latest")
			    if err != nil {
				log.Debug("===========ChooseRealFusionAccountForLockout,rpc call fail.==================")
				iter.Release() 
				db.Close() 
				cancel()
				lock.Unlock()
				return "","",errors.New("rpc call fail.")
			    }

			    ba := (*big.Int)(&result)
			    var m DcrmAddrInfo
			    m.DcrmAddr = key
			    m.FusionAccount = s[0]
			    m.CoinType = cointype
			    m.Balance = ba
			    dai = append(dai,m)
			    log.Debug("=========ChooseRealFusionAccountForLockout","dai",dai,"","========")
			     sort.Sort(DcrmAddrInfoWrapper{dai, func(p, q *DcrmAddrInfo) bool {
				    return q.Balance.Cmp(p.Balance) <= 0 //q.Age < p.Age
				}})
			    log.Debug("=========ChooseRealFusionAccountForLockout","dai",dai,"","========")

			    va,_ := new(big.Int).SetString(amount,10)
			     total := new(big.Int).Add(va,ETH_DEFAULT_FEE)
			    if ba.Cmp(total) >= 0 {
				iter.Release() 
				db.Close() 
				cancel()
				lock.Unlock()
				return s[0],key,nil
			    }
			}
			/////
		    } else { //BTC
			////
		    }
		}
	    }
	} 

	if len(dai) < 1 {
	    iter.Release() 
	    db.Close() 
	    cancel()
	    lock.Unlock()
	    return "","",errors.New("no get real fusion account to lockout.")
	}
	
	va,_ := new(big.Int).SetString(amount,10)
	va = new(big.Int).Add(va,ETH_DEFAULT_FEE)
	var bn *big.Int
	for i,v := range dai {
	    if i == 0 {
		bn = v.Balance
	    } else {
		if v.Balance.Cmp(ETH_DEFAULT_FEE) >= 0 {
		    d := new(big.Int).Sub(v.Balance,ETH_DEFAULT_FEE)
		    bn = new(big.Int).Add(bn,d)
		}
	    }
	}

	if bn.Cmp(va) < 0 {
	    iter.Release() 
	    db.Close() 
	    cancel()
	    lock.Unlock()
	    return "","",errors.New("no get real fusion account to lockout.")
	}

	mergenum = 0
	count := 0
	var fa string
	var fn string
	for i,v := range dai {
	    if i == 0 {
		fn = v.FusionAccount
		fa = v.DcrmAddr
		bn = v.Balance
	    } else {
		if v.Balance.Cmp(ETH_DEFAULT_FEE) >= 0 {
		    d := new(big.Int).Sub(v.Balance,ETH_DEFAULT_FEE)
		    bn = new(big.Int).Add(bn,d)
		    count++
		    go MergeDcrmBalance(v.FusionAccount,v.DcrmAddr,fa,d,cointype)
		    if bn.Cmp(va) >= 0 {
			break
		    }
		}
	    }
	}

	////
	times := 0
	for {
	    times++
	    if times == 400 {
		iter.Release() 
		db.Close() 
		cancel()
		lock.Unlock()
		return "","",errors.New("no get real fusion account to lockout.")
	    }

	    if mergenum == count {
		iter.Release() 
		db.Close() 
		cancel()
		lock.Unlock()
		return fn,fa,nil
	    }
	     
	    time.Sleep(time.Duration(10)*time.Second) //1000 == 1s
	}
	////
	
	iter.Release() 
	db.Close() 
	cancel()
	lock.Unlock()
    }

    if strings.EqualFold(cointype,"BTC") == true {
	lock.Lock()
	dbpath := GetDbDir()
	log.Debug("===========ChooseRealFusionAccountForLockout,","db path",dbpath,"","===============")
	db, err := leveldb.OpenFile(dbpath, nil) 
	if err != nil { 
	    log.Debug("===========ChooseRealFusionAccountForLockout,ERROR: Cannot open LevelDB.==================")
	    lock.Unlock()
	    return "","",errors.New("ERROR: Cannot open LevelDB.")
	} 
    
	var b bytes.Buffer 
	b.WriteString("") 
	b.WriteByte(0) 
	b.WriteString("") 
	iter := db.NewIterator(nil, nil) 
	for iter.Next() { 
	    key := string(iter.Key())
	    value := string(iter.Value())
	    log.Debug("===========ChooseRealFusionAccountForLockout,","key",key,"","===============")

	    s := strings.Split(value,sep)
	    if len(s) != 0 {
		var m AccountListInfo
		ok := json.Unmarshal([]byte(s[0]), &m)
		if ok == nil {
		    ////
		} else {
		    dcrmaddrs := []rune(key)
		    if len(dcrmaddrs) == 42 { //ETH
			////////
		    } else { //BTC
			va,_ := strconv.ParseFloat(amount, 64)
			var m DcrmAddrInfo
			m.DcrmAddr = key
			m.FusionAccount = s[0]
			m.CoinType = cointype
			ba,_ := GetDcrmAddrBalanceForLockout(key,lockoutto,va)
			m.Balance = ba
			dai = append(dai,m)
			log.Debug("=========ChooseRealFusionAccountForLockout","dai",dai,"","========")
			 sort.Sort(DcrmAddrInfoWrapper{dai, func(p, q *DcrmAddrInfo) bool {
				return q.Balance.Cmp(p.Balance) <= 0 //q.Age < p.Age
			    }})

			log.Debug("=========ChooseRealFusionAccountForLockout","dai",dai,"","========")
			if ChooseDcrmAddrForLockoutByValue(key,lockoutto,va) {
			    log.Debug("=========choose btc dcrm success.=============")
			    iter.Release() 
			    db.Close() 
			    lock.Unlock()
			    return s[0],key,nil
			}
		    }
		}
	    }
	} 
	
	if len(dai) < 1 {
	    iter.Release() 
	    db.Close() 
	    lock.Unlock()
	    return "","",errors.New("no get real fusion account to lockout.")
	}
	
	va,_ := strconv.ParseFloat(amount, 64)
	toa := GetTxOutsAmount(lockoutto,va)
	if toa == nil {
	    iter.Release() 
	    db.Close() 
	    lock.Unlock()
	    return "","",errors.New("no get real fusion account to lockout.")
	}

	fee,err:= GetBTCTxFee(lockoutto,va)
	if err != nil {
	    iter.Release() 
	    db.Close() 
	    lock.Unlock()
	    return "","",errors.New("no get real fusion account to lockout.")
	}

	var bn *big.Int
	for i,v := range dai {
	    if i == 0 {
		bn = v.Balance
	    } else {
		if v.Balance.Cmp(fee) >= 0 {
		    d := new(big.Int).Sub(v.Balance,fee)
		    bn = new(big.Int).Add(bn,d)
		}
	    }
	}

	if bn.Cmp(toa) < 0 {
	    iter.Release() 
	    db.Close() 
	    lock.Unlock()
	    return "","",errors.New("no get real fusion account to lockout.")
	}

	mergenum = 0
	count := 0
	var fa string
	var fn string
	for i,v := range dai {
	    if i == 0 {
		fn = v.FusionAccount
		fa = v.DcrmAddr
		bn = v.Balance
	    } else {
		if v.Balance.Cmp(fee) >= 0 {
		    d := new(big.Int).Sub(v.Balance,fee)
		    bn = new(big.Int).Add(bn,d)
		    count++
		    go MergeDcrmBalance(v.FusionAccount,v.DcrmAddr,fa,d,cointype)
		    if bn.Cmp(toa) >= 0 {
			break
		    }
		}
	    }
	}

	////
	times := 0
	for {
	    times++
	    if times == 400 {
		iter.Release() 
		db.Close() 
		lock.Unlock()
		return "","",errors.New("no get real fusion account to lockout.")
	    }

	    if mergenum == count {
		iter.Release() 
		db.Close() 
		lock.Unlock()
		return fn,fa,nil
	    }
	     
	    time.Sleep(time.Duration(10)*time.Second) //1000 == 1s
	}
	////
	
	iter.Release() 
	db.Close() 
	lock.Unlock()
    }

    return "","",errors.New("no get real fusion account to lockout.")
}

func IsValidFusionAddr(s string) bool {
    if s == "" {
	return false
    }

    fusions := []rune(s)
    if string(fusions[0:2]) == "0x" && len(fusions) != 42 { //42 = 2 + 20*2 =====>0x + addr
	return false
    }
    if string(fusions[0:2]) != "0x" {
	return false
    }

    return true
}

func IsValidDcrmAddr(s string,cointype string) bool {
    if s == "" || cointype == "" {
	return false
    }

    if (strings.EqualFold(cointype,"ETH") == true || strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true) && IsValidFusionAddr(s) == true { 
	return true 
    }
    if strings.EqualFold(cointype,"BTC") == true && ValidateAddress(1,s) == true {
	return true
    }

    return false

}

func getLockoutTx(realfusionfrom string,realdcrmfrom string,to string,value string,cointype string) (*types.Transaction,error) {
    if strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
	if erc20_client == nil { 
	    erc20_client,err := ethclient.Dial(ETH_SERVER)
	    if erc20_client == nil || err != nil {
		    log.Debug("===========getLockouTx,rpc dial fail.==================")
		    return nil,err
	    }
	}
	amount, _ := new(big.Int).SetString(value,10)
	gasLimit := uint64(0)
	tx, _, err := Erc20_newUnsignedTransaction(erc20_client, realdcrmfrom, to, amount, nil, gasLimit, cointype)
	if err != nil {
		log.Debug("===========getLockouTx,new tx fail.==================")
		return nil,err
	}

	return tx,nil
    }
    
    // Set receive address
    toAcc := common.HexToAddress(to)

    if strings.EqualFold(cointype,"ETH") {
	amount,_ := new(big.Int).SetString(value,10)

	//////////////
	 client, err := rpc.Dial(ETH_SERVER)
	if err != nil {
		log.Debug("===========getLockouTx,rpc dial fail.==================")
		return nil,err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var result hexutil.Uint64
	err = client.CallContext(ctx, &result, "eth_getTransactionCount",realdcrmfrom,"latest")
	if err != nil {
	    return nil,err
	}

	nonce := uint64(result)
	log.Debug("============getLockouTx,","not pending nonce",nonce,"","========")

	////
	/*fromAddress := common.HexToAddress(realdcrmfrom)
	client2,err2 := ethclient.Dial(ETH_SERVER)
	if err2 == nil {
	    nonce2, err2 := client2.PendingNonceAt(context.Background(), fromAddress)
	    if err2 == nil {
		nonce += nonce2
		log.Debug("============getLockouTx,","pending nonce",nonce,"","========")
	    }
	}*/
	////

	///////////////
	// New transaction
	tx := types.NewTransaction(
	    uint64(nonce),   // nonce 
	    toAcc,  // receive address
	    //big.NewInt(amount), // amount
	    amount,
	    48000, // gasLimit
	    big.NewInt(41000000000), // gasPrice
	    []byte(`dcrm lockout`)) // data

	if tx == nil {
	    return nil,errors.New("new eth tx fail.")
	}

	return tx,nil
    }

    return nil,errors.New("new eth tx fail.")
}

type Backend interface {
	//BlockChain() *core.BlockChain
	//TxPool() *core.TxPool
	Etherbase() (eb common.Address, err error)
	ChainDb() ethdb.Database
}

func SetBackend(e Backend) {
    FSN = e
}

func ChainDb() ethdb.Database {
    return FSN.ChainDb()
}

func Coinbase() (eb common.Address, err error) {
    return FSN.Etherbase()
}

func SendReqToGroup(msg string,rpctype string) (string,error) {
    var req RpcReq
    switch rpctype {
	case "rpc_confirm_dcrmaddr":
	    m := strings.Split(msg,sep9)
	    v := ConfirmAddrSendMsgToDcrm{Txhash:m[0],Tx:m[1],FusionAddr:m[2],DcrmAddr:m[3],Hashkey:m[4],Cointype:m[5]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_req_dcrmaddr":
	    m := strings.Split(msg,sep9)
	    v := ReqAddrSendMsgToDcrm{Fusionaddr:m[0],Pub:m[1],Cointype:m[2]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_lockin":
	    m := strings.Split(msg,sep9)
	    v := LockInSendMsgToDcrm{Txhash:m[0],Tx:m[1],Fusionaddr:m[2],Hashkey:m[3],Value:m[4],Cointype:m[5],LockinAddr:m[6],RealDcrmFrom:m[7]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_lockout":
	    m := strings.Split(msg,sep9)
	    v := LockoutSendMsgToDcrm{Txhash:m[0],Tx:m[1],FusionFrom:m[2],DcrmFrom:m[3],RealFusionFrom:m[4],RealDcrmFrom:m[5],Lockoutto:m[6],Value:m[7],Cointype:m[8]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_check_hashkey":
	    m := strings.Split(msg,sep9)
	    v := CheckHashkeySendMsgToDcrm{Txhash:m[0],Tx:m[1],Hashkey:m[2]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	default:
	    return "",nil
    }

    var t int
    if rpctype == "rpc_lockout" || rpctype == "rpc_lockin" {
	t = 360
    } else {
	t = 80 
    }

    if !IsInGroup() {
	RpcReqNonDcrmQueue <- req
    } else {
	RpcReqQueue <- req
    }
    //ret := (<- req.ch).(RpcDcrmRes)
    chret,cherr := GetChannelValue(t,req.ch)
    if cherr != nil {
	log.Debug("=============SendReqToGroup,fail,","error",cherr.Error(),"","==============")
	return "",cherr
    }

    log.Debug("SendReqToGroup","ret",chret)
    return chret,cherr
}

func SendMsgToDcrmGroup(msg string) {
    p2pdcrm.SendMsg(msg)
}

func SendMsgToDcrmGroup2(msg string) {
    ns,nodes := p2pdcrm.GetEnodes()
    if ns != TOTALNODES {
	return
    }
    
    others := strings.Split(nodes,sep2)
    for _,v := range others {
	if IsCurNode(v,cur_enode) {
	    continue
	}

	p2pdcrm.SendMsgToPeer(v,msg)
    }
}

func submitTransaction(tx *types.Transaction) (common.Hash, error) {
    /*err := FSN.TxPool().AddLocal(tx)
    if err != nil {
	    return common.Hash{}, err
    }*///tmp
    return tx.Hash(), nil
}

///////////////////////////////////////
type WorkReq interface {
    Run(workid int,ch chan interface{}) bool
}

//RecvMsg
type RecvMsg struct{
    msg string
}

func (self *RecvMsg) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    log.Debug("==========RecvMsg.Run,","receiv msg",self.msg,"","===================")
    mm := strings.Split(self.msg,msgtypesep)
    if len(mm) != 2 {
	DisMsg(self.msg)
	return true 
    }
    
    w := workers[workid]
    var msgCode string 
    msgCode = mm[1]

    if msgCode == "rpc_req_dcrmaddr" {
	mmm := strings.Split(mm[0],sep)
	prex := mmm[0]
	types.SetDcrmRpcWorkersData(prex,strconv.Itoa(workid))
	dcrm_liloreqAddress(prex,mmm[1],mmm[2],mmm[3],ch)
	ret,cherr := GetChannelValue(ch_t,ch)
	if cherr != nil {
	    log.Debug(cherr.Error())
	    msg := prex + sep + "fail" + msgtypesep + "rpc_req_dcrmaddr_res"
	    types.SetDcrmRpcResData(prex,msg)
	    p2pdcrm.Broatcast(msg)
	    go func(s string) {
		 time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
		 types.DeleteDcrmRpcMsgData(s)
		 types.DeleteDcrmRpcWorkersData(s)
		 types.DeleteDcrmRpcResData(s)
	    }(prex)
	    return false
	}
	msg := prex + sep + ret + msgtypesep + "rpc_req_dcrmaddr_res"
	types.SetDcrmRpcResData(prex,msg)
	p2pdcrm.Broatcast(msg)
	go func(s string) {
	     time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
	     types.DeleteDcrmRpcMsgData(s)
	     types.DeleteDcrmRpcWorkersData(s)
	     types.DeleteDcrmRpcResData(s)
	}(prex)
	return true 
    }

    if msgCode == "rpc_confirm_dcrmaddr" {
	mmm := strings.Split(mm[0],sep)
	prex := mmm[0]
	types.SetDcrmRpcWorkersData(prex,strconv.Itoa(workid))
	dcrm_confirmaddr(prex,mmm[1],mmm[2],mmm[3],mmm[4],mmm[5],mmm[6],ch)
	ret,cherr := GetChannelValue(ch_t,ch)
	if cherr != nil {
	    log.Debug(cherr.Error())
	    msg := prex + sep + "fail" + msgtypesep + "rpc_confirm_dcrmaddr_res"
	    types.SetDcrmRpcResData(prex,msg)
	    p2pdcrm.Broatcast(msg)
	    go func(s string) {
		 time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
		 types.DeleteDcrmRpcMsgData(s)
		 types.DeleteDcrmRpcWorkersData(s)
		 types.DeleteDcrmRpcResData(s)
	    }(prex)
	    return false
	}
	msg := prex + sep + ret + msgtypesep + "rpc_confirm_dcrmaddr_res"
	types.SetDcrmRpcResData(prex,msg)
	p2pdcrm.Broatcast(msg)
	go func(s string) {
	     time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
	     types.DeleteDcrmRpcMsgData(s)
	     types.DeleteDcrmRpcWorkersData(s)
	     types.DeleteDcrmRpcResData(s)
	}(prex)
	return true 
    }

    if msgCode == "rpc_lockin" {
	mmm := strings.Split(mm[0],sep)
	prex := mmm[0]
	types.SetDcrmRpcWorkersData(prex,strconv.Itoa(workid))
	validate_txhash(prex,mmm[2],mmm[7],mmm[4],mmm[8],ch)
	ret,cherr := GetChannelValue(ch_t,ch)
	if cherr != nil {
	    log.Debug(cherr.Error())
	    msg := prex + sep + "fail" + msgtypesep + "rpc_lockin_res"
	    types.SetDcrmRpcResData(prex,msg)
	    p2pdcrm.Broatcast(msg)
	    go func(s string) {
		 time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
		 types.DeleteDcrmRpcMsgData(s)
		 types.DeleteDcrmRpcWorkersData(s)
		 types.DeleteDcrmRpcResData(s)
	    }(prex)
	    return false
	}
	msg := prex + sep + ret + msgtypesep + "rpc_lockin_res"
	types.SetDcrmRpcResData(prex,msg)
	p2pdcrm.Broatcast(msg)
	go func(s string) {
	     time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
	     types.DeleteDcrmRpcMsgData(s)
	     types.DeleteDcrmRpcWorkersData(s)
	     types.DeleteDcrmRpcResData(s)
	}(prex)
	return true 
    }

    if msgCode == "rpc_lockout" {
	log.Debug("============RecvMsg.Run,msgCode == rpc_lockout===========")
	mmm := strings.Split(mm[0],sep)
	prex := mmm[0]
	types.SetDcrmRpcWorkersData(prex,strconv.Itoa(workid))

	//bug
	val,ok := GetLockoutInfoFromLocalDB(mmm[1])
	if ok == nil && val != "" {
	    log.Debug("============RecvMsg.Run,msgCode == rpc_lockout1111111111.===========")
	    types.SetDcrmValidateData(mmm[1],val)
	    msg := prex + sep + val + msgtypesep + "rpc_lockout_res"
	    types.SetDcrmRpcResData(prex,msg)
	    p2pdcrm.Broatcast(msg)
	    go func(s string) {
		 time.Sleep(time.Duration(500)*time.Second) //1000 == 1s
		 types.DeleteDcrmRpcMsgData(s)
		 types.DeleteDcrmRpcWorkersData(s)
		 types.DeleteDcrmRpcResData(s)
	    }(prex)
	    return true
	}
	//
	realfusionfrom,realdcrmfrom,err := ChooseRealFusionAccountForLockout(mmm[8],mmm[7],mmm[9])
	if err != nil {
	    log.Debug("============get real fusion/dcrm from fail.===========")
	    msg := prex + sep + "fail" + msgtypesep + "rpc_lockout_res"
	    types.SetDcrmRpcResData(prex,msg)
	    p2pdcrm.Broatcast(msg)
	    go func(s string) {
		 time.Sleep(time.Duration(500)*time.Second) //1000 == 1s
		 types.DeleteDcrmRpcMsgData(s)
		 types.DeleteDcrmRpcWorkersData(s)
		 types.DeleteDcrmRpcResData(s)
	    }(prex)
	    return false
	}

	if IsValidFusionAddr(realfusionfrom) == false {
	    log.Debug("============validate real fusion from fail.===========")
	    msg := prex + sep + "fail" + msgtypesep + "rpc_lockout_res"
	    types.SetDcrmRpcResData(prex,msg)
	    p2pdcrm.Broatcast(msg)
	    go func(s string) {
		 time.Sleep(time.Duration(500)*time.Second) //1000 == 1s
		 types.DeleteDcrmRpcMsgData(s)
		 types.DeleteDcrmRpcWorkersData(s)
		 types.DeleteDcrmRpcResData(s)
	    }(prex)
	    return false
	}
	if IsValidDcrmAddr(realdcrmfrom,mmm[9]) == false {
	    log.Debug("============validate real dcrm from fail.===========")
	    msg := prex + sep + "fail" + msgtypesep + "rpc_lockout_res"
	    types.SetDcrmRpcResData(prex,msg)
	    p2pdcrm.Broatcast(msg)
	    go func(s string) {
		 time.Sleep(time.Duration(500)*time.Second) //1000 == 1s
		 types.DeleteDcrmRpcMsgData(s)
		 types.DeleteDcrmRpcWorkersData(s)
		 types.DeleteDcrmRpcResData(s)
	    }(prex)
	    return false
	}

	validate_lockout(prex,mmm[1],mmm[2],mmm[3],mmm[4],realfusionfrom,realdcrmfrom,mmm[7],mmm[8],mmm[9],ch)
	ret,cherr := GetChannelValue(ch_t,ch)
	if cherr != nil {
	    log.Debug("============RecvMsg.Run,msgCode == rpc_lockout222222222.===========")
	    log.Debug(cherr.Error())
	    msg := prex + sep + "fail" + msgtypesep + "rpc_lockout_res"
	    types.SetDcrmRpcResData(prex,msg)
	    p2pdcrm.Broatcast(msg)
	    go func(s string) {
		 time.Sleep(time.Duration(500)*time.Second) //1000 == 1s
		 types.DeleteDcrmRpcMsgData(s)
		 types.DeleteDcrmRpcWorkersData(s)
		 types.DeleteDcrmRpcResData(s)
	    }(prex)
	    return false
	}
	msg := prex + sep + ret + msgtypesep + "rpc_lockout_res"
	types.SetDcrmRpcResData(prex,msg)
	p2pdcrm.Broatcast(msg)
	go func(s string) {
	     time.Sleep(time.Duration(500)*time.Second) //1000 == 1s
	     types.DeleteDcrmRpcMsgData(s)
	     types.DeleteDcrmRpcWorkersData(s)
	     types.DeleteDcrmRpcResData(s)
	}(prex)
	return true 
    }

    if msgCode == "startdcrm" {
	GetEnodesInfo()
	msgs := mm[0] + "-" + cur_enode + "-" + strconv.Itoa(w.id) + msgtypesep + "syncworkerid"
	log.Debug("===========","RecvMsg.Run,send workid,msgs",msgs,"","===============")
	SendMsgToDcrmGroup(msgs)
	//<-w.brealstartdcrm
	_,cherr := GetChannelValue(ch_t,w.brealstartdcrm)
	if cherr != nil {
	    log.Debug("get w.brealstartdcrm timeout.")
	    return false
	}

	//wm := <-w.msgprex
	wm,cherr := GetChannelValue(ch_t,w.msgprex)
	if cherr != nil {
	    log.Debug("get w.msgprex timeout.")
	    return false
	}

	log.Debug("===========RecvMsg.Run,get real start dcrm.===============")
	funs := strings.Split(wm, "-")

	if funs[0] == "Dcrm_ReqAddress" {
	    //wpub := <-w.pub
	    //wcoint := <-w.coint

	    wpub,cherr := GetChannelValue(ch_t,w.pub)
	    if cherr != nil {
		log.Debug("get w.pub timeout.")
		return false
	    }
	    wcoint,cherr := GetChannelValue(ch_t,w.coint)
	    if cherr != nil {
		log.Debug("get w.coint timeout.")
		return false
	    }

	    dcrm_reqAddress(wm,wpub,wcoint,ch)
	}
	if funs[0] == "Dcrm_ConfirmAddr" {
	    //wtxhash_conaddr := <-w.txhash_conaddr
	    wtxhash_conaddr,cherr := GetChannelValue(ch_t,w.txhash_conaddr)
	    if cherr != nil {
		log.Debug("get w.txhash_conaddr timeout.")
		return false
	    }
	    //wlilotx := <-w.lilotx
	    wlilotx,cherr := GetChannelValue(ch_t,w.lilotx)
	    if cherr != nil {
		log.Debug("get w.lilotx timeout.")
		return false
	    }
	    //wfusionaddr := <-w.fusionaddr
	    wfusionaddr,cherr := GetChannelValue(ch_t,w.fusionaddr)
	    if cherr != nil {
		log.Debug("get w.fusionaddr timeout.")
		return false
	    }
	    //wdcrmaddr := <-w.dcrmaddr
	    wdcrmaddr,cherr := GetChannelValue(ch_t,w.dcrmaddr)
	    if cherr != nil {
		log.Debug("get w.dcrmaddr timeout.")
		return false
	    }
	    //whashkey := <-w.hashkey
	    whashkey,cherr := GetChannelValue(ch_t,w.hashkey)
	    if cherr != nil {
		log.Debug("get w.hashkey timeout.")
		return false
	    }
	    //wcoint := <-w.coint
	    wcoint,cherr := GetChannelValue(ch_t,w.coint)
	    if cherr != nil {
		log.Debug("get w.coint timeout.")
		return false
	    }
	    dcrm_confirmaddr(wm,wtxhash_conaddr,wlilotx,wfusionaddr,wdcrmaddr,whashkey,wcoint,ch)
	}
	if funs[0] == "Dcrm_LiLoReqAddress" {
	    //log.Debug("RecvMsg.Run,Dcrm_LiLoReqAddress")
	    //wfusionaddr := <-w.fusionaddr
	    wfusionaddr,cherr := GetChannelValue(ch_t,w.fusionaddr)
	    if cherr != nil {
		log.Debug("get w.fusionaddr timeout.")
		return false
	    }
	    //wpub := <-w.pub
	    wpub,cherr := GetChannelValue(ch_t,w.pub)
	    if cherr != nil {
		log.Debug("get w.pub timeout.")
		return false
	    }
	    //wcoint := <-w.coint
	    wcoint,cherr := GetChannelValue(ch_t,w.coint)
	    if cherr != nil {
		log.Debug("get w.coint timeout.")
		return false
	    }
	    dcrm_liloreqAddress(wm,wfusionaddr,wpub,wcoint,ch)
	   // log.Debug("==========RecvMsg.Run,dcrm_liloreqAddress,ret ch.=====================")
	}
	if funs[0] == "Dcrm_Sign" {
	    //wsig := <-w.sig
	    wsig,cherr := GetChannelValue(ch_t,w.sig)
	    if cherr != nil {
		log.Debug("get w.wsig timeout.")
		return false
	    }
	    //wtxhash := <-w.txhash
	    wtxhash,cherr := GetChannelValue(ch_t,w.txhash)
	    if cherr != nil {
		log.Debug("get w.txhash timeout.")
		return false
	    }
	    //wdcrmaddr := <-w.dcrmaddr
	    wdcrmaddr,cherr := GetChannelValue(ch_t,w.dcrmaddr)
	    if cherr != nil {
		log.Debug("get w.dcrmaddr timeout.")
		return false
	    }
	    //wcoint := <-w.coint
	    wcoint,cherr := GetChannelValue(ch_t,w.coint)
	    if cherr != nil {
		log.Debug("get w.coint timeout.")
		return false
	    }
	    dcrm_sign(wm,wsig,wtxhash,wdcrmaddr,wcoint,ch)
	}
	if funs[0] == "Validate_Lockout" {
	    //wtxhash_lockout := <- w.txhash_lockout
	    wtxhash_lockout,cherr := GetChannelValue(ch_t,w.txhash_lockout)
	    if cherr != nil {
		log.Debug("get w.txhash_lockout timeout.")
		return false
	    }
	    //wlilotx := <- w.lilotx
	    wlilotx,cherr := GetChannelValue(ch_t,w.lilotx)
	    if cherr != nil {
		log.Debug("get w.lilotx timeout.")
		return false
	    }
	    //wfusionfrom := <- w.fusionfrom
	    wfusionfrom,cherr := GetChannelValue(ch_t,w.fusionfrom)
	    if cherr != nil {
		log.Debug("get w.fusionfrom timeout.")
		return false
	    }
	    //wdcrmfrom := <- w.dcrmfrom
	    wdcrmfrom,cherr := GetChannelValue(ch_t,w.dcrmfrom)
	    if cherr != nil {
		log.Debug("get w.dcrmfrom timeout.")
		return false
	    }
	    //wrealfusionfrom := <- w.realfusionfrom
	    wrealfusionfrom,cherr := GetChannelValue(ch_t,w.realfusionfrom)
	    if cherr != nil {
		log.Debug("get w.realfusionfrom timeout.")
		return false
	    }
	    //wrealdcrmfrom := <- w.realdcrmfrom
	    wrealdcrmfrom,cherr := GetChannelValue(ch_t,w.realdcrmfrom)
	    if cherr != nil {
		log.Debug("get w.realdcrmfrom timeout.")
		return false
	    }
	    //wlockoutto := <- w.lockoutto
	    wlockoutto,cherr := GetChannelValue(ch_t,w.lockoutto)
	    if cherr != nil {
		log.Debug("get w.lockoutto timeout.")
		return false
	    }
	    //wamount := <- w.amount
	    wamount,cherr := GetChannelValue(ch_t,w.amount)
	    if cherr != nil {
		log.Debug("get w.amount timeout.")
		return false
	    }
	    //wcoint := <- w.coint
	    wcoint,cherr := GetChannelValue(ch_t,w.coint)
	    if cherr != nil {
		log.Debug("get w.coint timeout.")
		return false
	    }

	    log.Debug("==========RecvMsg.Run,start call validate_lockout.=====================")
	    validate_lockout(wm,wtxhash_lockout,wlilotx,wfusionfrom,wdcrmfrom,wrealfusionfrom,wrealdcrmfrom,wlockoutto,wamount,wcoint,ch)
	}

	return true
    }

    if msgCode == "syncworkerid" {
	log.Debug("========RecvMsg.Run,receiv syncworkerid msg.============")
	GetEnodesInfo()
	sh := mm[0] 
	shs := strings.Split(sh, "-")
	//bug
	if len(shs) < 2 {
	    return false
	}
	//
	en := shs[1]
	//bug
	if en == cur_enode && len(shs) < 6 {
	    return false
	}
	//
	if en == cur_enode {
	    id,_ := strconv.Atoi(shs[3])
	    id2,_ := strconv.Atoi(shs[5])
	    workers[id].ch_nodeworkid <- NodeWorkId{enode:shs[4],workid:id2}
	    if len(workers[id].ch_nodeworkid) == (NodeCnt-1) {
	//	log.Debug("========RecvMsg.Run,it is ready.============")
		workers[id].bidsready <- true
	    }
	}

	return true
    }

    if msgCode == "realstartdcrm" {
	GetEnodesInfo()
	sh := mm[0]
	log.Debug("=============","RecvMsg.Run,real start dcrm msg",sh,"","=================")
	shs := strings.Split(sh, sep)
	//log.Debug("=============","RecvMsg.Run,real start dcrm msg len",len(shs),"","=================")
	id := getworkerid(shs[0],cur_enode)
	//log.Debug("=============","RecvMsg.Run,real start dcrm id",id,"","=================")
	workers[id].msgprex <- shs[0]
	funs := strings.Split(shs[0],"-")
	if funs[0] == "Dcrm_ReqAddress" {
	    if len(shs) < 3 {
		return false
	    }
	    workers[id].pub <- shs[1]
	    workers[id].coint <- shs[2]
	}
	if funs[0] == "Dcrm_ConfirmAddr" {
	    if len(shs) < 7 {
		return false
	    }
	    vv := shs[1]
	    workers[id].txhash_conaddr <- vv
	    workers[id].lilotx <- shs[2]
	    workers[id].fusionaddr <- shs[3]
	    workers[id].dcrmaddr <- shs[4]
	    workers[id].hashkey <- shs[5]
	    workers[id].coint <- shs[6]
	}
	if funs[0] == "Dcrm_LiLoReqAddress" {
	  //  log.Debug("RecvMsg.Run,Dcrm_LiLoReqAddress,real start req addr.")
	    if len(shs) < 4 {
		return false
	    }
	    workers[id].fusionaddr <- shs[1]
	    workers[id].pub <- shs[2]
	    workers[id].coint <- shs[3]
	}
	if funs[0] == "Dcrm_Sign" {
	    if len(shs) < 5 {
		return false
	    }
	    workers[id].sig <- shs[1]
	    workers[id].txhash <- shs[2]
	    workers[id].dcrmaddr <- shs[3]
	    workers[id].coint <- shs[4]
	}
	if funs[0] == "Validate_Lockout" {
	    if len(shs) < 10 {
		return false
	    }
	    workers[id].txhash_lockout <- shs[1]
	    workers[id].lilotx <- shs[2]
	    workers[id].fusionfrom <- shs[3]
	    workers[id].dcrmfrom <- shs[4]
	    workers[id].realfusionfrom <- shs[5]
	    workers[id].realdcrmfrom <- shs[6]
	    workers[id].lockoutto <- shs[7]
	    workers[id].amount <- shs[8]
	    workers[id].coint <- shs[9]
	}

	workers[id].brealstartdcrm <- true

	return true
    }
    
    if msgCode == "startvalidate" {
	log.Debug("========RecvMsg.Run,receiv startvalidate msg.============")
	GetEnodesInfo()
	msgs := mm[0] + "-" + cur_enode + "-" + strconv.Itoa(w.id) + msgtypesep + "syncworkerid"
	SendMsgToDcrmGroup(msgs)
	//<-w.brealstartvalidate
	_,cherr := GetChannelValue(ch_t,w.brealstartvalidate)
	if cherr != nil {
	    log.Debug("get w.brealstartvalidate timeout.")
	    return false
	}
	//log.Debug("========RecvMsg.Run,real start validate.============")
	//wm := <-w.msgprex
	wm,cherr := GetChannelValue(ch_t,w.msgprex)
	if cherr != nil {
	    log.Debug("get w.msgprex timeout.")
	    return false
	}
	funs := strings.Split(wm, "-")

	if funs[0] == "Validate_Txhash" {
	    //wtx := <-w.tx
	    wtx,cherr := GetChannelValue(ch_t,w.tx)
	    if cherr != nil {
		log.Debug("get w.tx timeout.")
		return false
	    }
	    //wlockinaddr := <-w.lockinaddr
	    wlockinaddr,cherr := GetChannelValue(ch_t,w.lockinaddr)
	    if cherr != nil {
		log.Debug("get w.lockinaddr timeout.")
		return false
	    }
	    //whashkey := <-w.hashkey
	    whashkey,cherr := GetChannelValue(ch_t,w.hashkey)
	    if cherr != nil {
		log.Debug("get w.hashkey timeout.")
		return false
	    }
	    wrealdcrmfrom,cherr := GetChannelValue(ch_t,w.realdcrmfrom)
	    if cherr != nil {
		log.Debug("get w.realdcrmfrom timeout.")
		return false
	    }
	    validate_txhash(wm,wtx,wlockinaddr,whashkey,wrealdcrmfrom,ch)
	}

	return true
    }

    if msgCode == "realstartvalidate" {
	log.Debug("========RecvMsg.Run,receiv realstartvalidate msg.============")
	GetEnodesInfo()
	sh := mm[0] 
	shs := strings.Split(sh, sep)
	id := getworkerid(shs[0],cur_enode)
	workers[id].msgprex <- shs[0]
	funs := strings.Split(shs[0],"-")
	if funs[0] == "Validate_Txhash" {
	    if len(shs) < 4 {
		return false
	    }
	    workers[id].tx <- shs[1]
	    workers[id].lockinaddr <- shs[2]
	    workers[id].hashkey <- shs[3]
	    workers[id].realdcrmfrom <- shs[4]
	}
	workers[id].brealstartvalidate <- true

	return true
    }

    if msgCode == "txhash_validate_pass" || msgCode == "txhash_validate_no_pass" {
	valiinfo := strings.Split(mm[0],sep)
	id := getworkerid(valiinfo[0],cur_enode)
	workers[id].msg_txvalidate <-self.msg
	if len(workers[id].msg_txvalidate) == (NodeCnt-1) {
	    workers[id].btxvalidate <- true
	}

	return true
    }

    if msgCode == "lilodcrmaddr" {
	valiinfo := strings.Split(mm[0],sep)
	id := getworkerid(valiinfo[0],cur_enode)
	workers[id].dcrmres <-valiinfo[1]
	if len(workers[id].dcrmres) == (NodeCnt-1) {
	    workers[id].bdcrmres <- true
	}

	return true
    }

    if msgCode == "lilodcrmsign" {
	valiinfo := strings.Split(mm[0],sep)
	id := getworkerid(valiinfo[0],cur_enode)
	workers[id].lockout_dcrmres <-valiinfo[1]
	if len(workers[id].lockout_dcrmres) == (NodeCnt-1) {
	    workers[id].lockout_bdcrmres <- true
	}

	return true
    }
    
    return true 
}

//DcrmReqAddress
type DcrmReqAddress struct{
    Pub string
    Cointype string
}

func (self *DcrmReqAddress) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
    ss := "Dcrm_ReqAddress" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startdcrm"
    SendMsgToDcrmGroup(ks)
    //<-w.bidsready
    _,cherr := GetChannelValue(ch_t,w.bidsready)
    if cherr != nil {
	log.Debug("get w.bidsready timeout.")
	return false
    }
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	//ni := <- w.ch_nodeworkid
	ni,cherr := GetChannelValue(ch_t,w.ch_nodeworkid)
	if cherr != nil {
	    log.Debug("get w.ch_nodeworkid timeout.")
	    return false
	}
	ss = ss + "-" + ni
	//ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Pub + sep + self.Cointype
    sss = sss + msgtypesep + "realstartdcrm"
    SendMsgToDcrmGroup(sss)
    dcrm_reqAddress(ss,self.Pub,self.Cointype,ch)
    return true
}

//DcrmConfirmAddr
type DcrmConfirmAddr struct {
    Txhash string
    Tx string
    FusionAddr string
    DcrmAddr string
    Hashkey string
    Cointype string
}

func (self *DcrmConfirmAddr) Run(workid int,ch chan interface{}) bool {

    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
    ss := "Dcrm_ConfirmAddr" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startdcrm"
    SendMsgToDcrmGroup(ks)
    //<-w.bidsready
    _,cherr := GetChannelValue(ch_t,w.bidsready)
    if cherr != nil {
	log.Debug("get w.bidsready timeout.")
	return false
    }
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	//ni := <- w.ch_nodeworkid
	ni,cherr := GetChannelValue(ch_t,w.ch_nodeworkid)
	if cherr != nil {
	    log.Debug("get w.ch_nodeworkid timeout.")
	    return false
	}
	ss = ss + "-" + ni
	//ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Txhash + sep + self.Tx + sep + self.FusionAddr + sep + self.DcrmAddr + sep + self.Hashkey + sep + self.Cointype
    sss = sss + msgtypesep + "realstartdcrm"
    SendMsgToDcrmGroup(sss)
    dcrm_confirmaddr(ss,self.Txhash,self.Tx,self.FusionAddr,self.DcrmAddr,self.Hashkey,self.Cointype,ch)
    return true
}

//DcrmLiLoReqAddress
type DcrmLiLoReqAddress struct{
    Fusionaddr string
    Pub string
    Cointype string
}

func (self *DcrmLiLoReqAddress) Run(workid int,ch chan interface{}) bool {

    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
    ss := "Dcrm_LiLoReqAddress" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startdcrm"
    //log.Debug("========","SendMsgToDcrmGroup,ks",ks,"","==========")
    SendMsgToDcrmGroup(ks)
    //<-w.bidsready
    _,cherr := GetChannelValue(ch_t,w.bidsready)
    if cherr != nil {
	log.Debug("get w.bidsready timeout.")
	return false
    }
    //log.Debug("DcrmLiLoReqAddress.Run,other nodes id is ready.")
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	//ni := <- w.ch_nodeworkid
	ni,cherr := GetChannelValue(ch_t,w.ch_nodeworkid)
	if cherr != nil {
	    log.Debug("get w.ch_nodeworkid timeout.")
	    return false
	}
	ss = ss + "-" + ni
	//ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Fusionaddr + sep + self.Pub + sep + self.Cointype 
    sss = sss + msgtypesep + "realstartdcrm"
    SendMsgToDcrmGroup(sss)
    //log.Debug("DcrmLiLoReqAddress.Run,start generate addr","msgprex",ss,"self.Fusionaddr",self.Fusionaddr,"self.Pub",self.Pub,"self.Cointype",self.Cointype)
    dcrm_liloreqAddress(ss,self.Fusionaddr,self.Pub,self.Cointype,ch)
    //log.Debug("==========DcrmLiLoReqAddress.Run,ret ch.=====================")
    return true
}

//DcrmSign
type DcrmSign struct{
    Sig string
    Txhash string
    DcrmAddr string
    Cointype string
}

func (self *DcrmSign) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
    ss := "Dcrm_Sign" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(w.id)

    ks := ss + msgtypesep + "startdcrm"
    SendMsgToDcrmGroup(ks)
    //<-w.bidsready
    _,cherr := GetChannelValue(ch_t,w.bidsready)
    if cherr != nil {
	log.Debug("get w.bidsready timeout.")
	return false
    }
    
    log.Debug("===================dcrm_sign get idsready finish.====================")
    
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	//ni := <- w.ch_nodeworkid
	ni,cherr := GetChannelValue(ch_t,w.ch_nodeworkid)
	if cherr != nil {
	    log.Debug("get w.ch_nodeworkid timeout.")
	    return false
	}
	ss = ss + "-" + ni
	//ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }
   
    sss := ss + sep + self.Sig + sep + self.Txhash + sep + self.DcrmAddr + sep + self.Cointype
    sss = sss + msgtypesep + "realstartdcrm"
    SendMsgToDcrmGroup(sss)
    log.Debug("===================Start dcrm_sign====================")
    //time.Sleep(time.Duration(50)*time.Second) //tmp
    dcrm_sign(ss,self.Sig,self.Txhash,self.DcrmAddr,self.Cointype,ch)
    return true
}

//DcrmLockin
type DcrmLockin struct {
    Tx string
    LockinAddr string
    Hashkey string
    RealDcrmFrom string
}

func (self *DcrmLockin) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    log.Debug("===============DcrmLockin.Run======================")
    GetEnodesInfo()
    w := workers[workid]
    ss := "Validate_Txhash" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startvalidate"
    SendMsgToDcrmGroup(ks)
    //<-w.bidsready
    _,cherr := GetChannelValue(ch_t,w.bidsready)
    if cherr != nil {
	log.Debug("get w.bidsready timeout.")
	return false
    }
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	//ni := <- w.ch_nodeworkid
	ni,cherr := GetChannelValue(ch_t,w.ch_nodeworkid)
	if cherr != nil {
	    log.Debug("get w.ch_nodeworkid timeout.")
	    return false
	}
	ss = ss + "-" + ni
	//ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    log.Debug("===============DcrmLockin.Run,start call validate_txhash ======================")
    sss := ss + sep + self.Tx + sep + self.LockinAddr + sep + self.Hashkey + sep + self.RealDcrmFrom
    sss = sss + msgtypesep + "realstartvalidate"
    SendMsgToDcrmGroup(sss)
    validate_txhash(ss,self.Tx,self.LockinAddr,self.Hashkey,self.RealDcrmFrom,ch)
    return true
}

//DcrmLockout
type DcrmLockout struct {
    Txhash string
    Tx string
    FusionFrom string
    DcrmFrom string
    RealFusionFrom string
    RealDcrmFrom string
    Lockoutto string
    Value string
    Cointype string
}

func (self *DcrmLockout) Run(workid int,ch chan interface{}) bool {

    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
    ss := "Validate_Lockout" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startdcrm"

    log.Debug("=============DcrmLockout.Run","send data",ks,"","=============")
    SendMsgToDcrmGroup(ks)
    //<-w.bidsready
    _,cherr := GetChannelValue(ch_t,w.bidsready)
    if cherr != nil {
	log.Debug("get w.bidsready timeout.")
	return false
    }
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	//ni := <- w.ch_nodeworkid
	ni,cherr := GetChannelValue(ch_t,w.ch_nodeworkid)
	if cherr != nil {
	    log.Debug("get w.ch_nodeworkid timeout.")
	    return false
	}
	ss = ss + "-" + ni
	//ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Txhash + sep + self.Tx + sep + self.FusionFrom + sep + self.DcrmFrom + sep + self.RealFusionFrom + sep + self.RealDcrmFrom + sep + self.Lockoutto + sep + self.Value + sep + self.Cointype
    sss = sss + msgtypesep + "realstartdcrm"
    log.Debug("=============DcrmLockout.Run","real start dcrm,send data",sss,"","=============")
    SendMsgToDcrmGroup(sss)
    validate_lockout(ss,self.Txhash,self.Tx,self.FusionFrom,self.DcrmFrom,self.RealFusionFrom,self.RealDcrmFrom,self.Lockoutto,self.Value,self.Cointype,ch)
    return true
}

//non dcrm,
type ConfirmAddrSendMsgToDcrm struct {
    Txhash string
    Tx string
    FusionAddr string
    DcrmAddr string
    Hashkey string
    Cointype string
}

func (self *ConfirmAddrSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    prex := cur_enode + "-" + "ConfirmAddr" + "-" + self.Txhash
    types.SetDcrmRpcWorkersData(prex,strconv.Itoa(workid))
    msg := prex + sep + self.Txhash + sep + self.Tx + sep + self.FusionAddr + sep + self.DcrmAddr + sep + self.Hashkey + sep + self.Cointype + msgtypesep + "rpc_confirm_dcrmaddr"
    types.SetDcrmRpcMsgData(prex,msg)
    log.Debug("ConfirmAddrSendMsgToDcrm.Run","broatcast rpc msg",msg)
    p2pdcrm.Broatcast(msg)

    go func(s string) {
	 time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
	 types.DeleteDcrmRpcMsgData(s)
	 types.DeleteDcrmRpcWorkersData(s)
	 types.DeleteDcrmRpcResData(s)
    }(prex)
   
    var data string
    var cherr error
    if !IsInGroup() {
	w := non_dcrm_workers[workid]
	data,cherr = GetChannelValue(ch_t,w.dcrmret)
    } else {
	dcrm_confirmaddr(prex,self.Txhash,self.Tx,self.FusionAddr,self.DcrmAddr,self.Hashkey,self.Cointype,ch)
	data2,cherr2 := GetChannelValue(ch_t,ch)
	if cherr2 != nil {
	    data = "fail"
	    cherr = nil
	} else {
	    data = data2
	    cherr = nil
	}
    }

    if cherr != nil {
	log.Debug("get w.dcrmret timeout.")
	var ret2 Err
	ret2.info = "get dcrm return result timeout." 
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    log.Debug("ConfirmAddrSendMsgToDcrm.Run","dcrm return result",data)

    if data == "fail" {
	log.Debug("confirm dcrm addr fail.")
	var ret2 Err
	ret2.info = "confirm dcrm addr fail." 
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    
    res := RpcDcrmRes{ret:data,err:nil}
    ch <- res
    return true
}

type ReqAddrSendMsgToDcrm struct {
    Fusionaddr string
    Pub string
    Cointype string
}

func (self *ReqAddrSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    one,_ := new(big.Int).SetString("1",10)
    rpcs = new(big.Int).Add(rpcs,one)
    tips := fmt.Sprintf("%v",rpcs)
    GetEnodesInfo()
    prex := cur_enode + "-" + "ReqAddr" + "-" + tips
    types.SetDcrmRpcWorkersData(prex,strconv.Itoa(workid))
    msg := prex + sep + self.Fusionaddr + sep + self.Pub + sep + self.Cointype + msgtypesep + "rpc_req_dcrmaddr"
    types.SetDcrmRpcMsgData(prex,msg)
    log.Debug("ReqAddrSendMsgToDcrm.Run","broatcast rpc msg",msg)
    p2pdcrm.Broatcast(msg)

    go func(s string) {
	 time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
	 types.DeleteDcrmRpcMsgData(s)
	 types.DeleteDcrmRpcWorkersData(s)
	 types.DeleteDcrmRpcResData(s)
    }(prex)
   
    var data string
    var cherr error
    if !IsInGroup() {
	w := non_dcrm_workers[workid]
	data,cherr = GetChannelValue(ch_t,w.dcrmret)
    } else {
	dcrm_liloreqAddress(prex,self.Fusionaddr,self.Pub,self.Cointype,ch)
	data2,cherr2 := GetChannelValue(ch_t,ch)
	if cherr2 != nil {
	    data = "fail"
	    cherr = nil
	} else {
	    data = data2
	    cherr = nil
	}
    }

    if cherr != nil {
	log.Debug("get w.dcrmret timeout.")
	var ret2 Err
	ret2.info = "get dcrm return result timeout." 
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    log.Debug("ReqAddrSendMsgToDcrm.Run","dcrm return result",data)

    if data == "fail" {
	log.Debug("req dcrm addr fail.")
	var ret2 Err
	ret2.info = "req dcrm addr fail." 
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    
    res := RpcDcrmRes{ret:data,err:nil}
    ch <- res
    return true
}

//lockin
type LockInSendMsgToDcrm struct {
    Txhash string
    Tx string
    Fusionaddr string
    Hashkey string
    Value string
    Cointype string
    LockinAddr string
    RealDcrmFrom string
}

func (self *LockInSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    prex := cur_enode + "-" + "LockIn" + "-" + self.Txhash
    types.SetDcrmRpcWorkersData(prex,strconv.Itoa(workid))
    msg := prex + sep + self.Txhash + sep + self.Tx + sep + self.Fusionaddr + sep + self.Hashkey + sep + self.Value + sep + self.Cointype + sep + self.LockinAddr + sep + self.RealDcrmFrom + msgtypesep + "rpc_lockin"
    types.SetDcrmRpcMsgData(prex,msg)
    log.Debug("LockInSendMsgToDcrm.Run","broacast rpc msg",msg)
    p2pdcrm.Broatcast(msg)

    go func(s string) {
	 time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
	 types.DeleteDcrmRpcMsgData(s)
	 types.DeleteDcrmRpcWorkersData(s)
	 types.DeleteDcrmRpcResData(s)
    }(prex)
   
    var data string
    var cherr error
    if !IsInGroup() {
	w := non_dcrm_workers[workid]
	data,cherr = GetChannelValue(ch_t,w.dcrmret)
    } else {
	validate_txhash(prex,self.Tx,self.LockinAddr,self.Hashkey,self.RealDcrmFrom,ch)
	data2,cherr2 := GetChannelValue(ch_t,ch)
	if cherr2 != nil {
	    data = "fail"
	    cherr = nil
	} else {
	    data = data2
	    cherr = nil
	}
    }
    
    if cherr != nil {
	log.Debug("get w.dcrmret timeout.")
	var ret2 Err
	ret2.info = "get dcrm return result timeout." 
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    log.Debug("LockInSendMsgToDcrm.Run","dcrm return result",data)

    if data == "fail" {
	log.Debug("dcrm lockin fail.")
	var ret2 Err
	ret2.info = "dcrm lockin fail." 
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    
    res := RpcDcrmRes{ret:data,err:nil}
    ch <- res
    return true
}

//lockout
type LockoutSendMsgToDcrm struct {
    Txhash string
    Tx string
    FusionFrom string
    DcrmFrom string
    RealFusionFrom string
    RealDcrmFrom string
    Lockoutto string
    Value string
    Cointype string
}

func (self *LockoutSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    prex := cur_enode + "-" + "LockOut" + "-" + self.Txhash
    types.SetDcrmRpcWorkersData(prex,strconv.Itoa(workid))
    msg := prex + sep + self.Txhash + sep + self.Tx + sep + self.FusionFrom + sep + self.DcrmFrom + sep + self.RealFusionFrom + sep + self.RealDcrmFrom + sep + self.Lockoutto + sep + self.Value + sep + self.Cointype + msgtypesep + "rpc_lockout"
    log.Debug("LockOutSendMsgToDcrm.Run","prex",prex)
    types.SetDcrmRpcMsgData(prex,msg)
    log.Debug("LockOutSendMsgToDcrm.Run","broacast rpc msg",msg)
    p2pdcrm.Broatcast(msg)

    go func(s string) {
	 time.Sleep(time.Duration(500)*time.Second) //1000 == 1s
	 types.DeleteDcrmRpcMsgData(s)
	 types.DeleteDcrmRpcWorkersData(s)
	 types.DeleteDcrmRpcResData(s)
    }(prex)
   
    var data string
    var cherr error
    if !IsInGroup() {
	w := non_dcrm_workers[workid]
	data,cherr = GetChannelValue(ch_t,w.dcrmret)
    } else {
	validate_lockout(prex,self.Txhash,self.Tx,self.FusionFrom,self.DcrmFrom,self.RealFusionFrom,self.RealDcrmFrom,self.Lockoutto,self.Value,self.Cointype,ch)
	data2,cherr2 := GetChannelValue(ch_t,ch)
	if cherr2 != nil {
	    data = "fail"
	    cherr = nil
	} else {
	    data = data2
	    cherr = nil
	}
    }
    
    if cherr != nil {
	log.Debug("get w.dcrmret timeout.")
	var ret2 Err
	ret2.info = "get dcrm return result timeout." 
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    log.Debug("LockOutSendMsgToDcrm.Run","dcrm return result",data)

    if data == "fail" {
	log.Debug("dcrm lockout fail.")
	var ret2 Err
	ret2.info = "dcrm lockout fail." 
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    
    res := RpcDcrmRes{ret:data,err:nil}
    ch <- res
    return true
}

//checkhashkey
type CheckHashkeySendMsgToDcrm struct {
    Txhash string
    Tx string
    Hashkey string
}

func (self *CheckHashkeySendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := non_dcrm_workers[workid]
    
    ss := cur_enode + "-" + self.Txhash + "-" + self.Tx + "-" + self.Hashkey + "-" + strconv.Itoa(workid) + msgtypesep + "rpc_check_hashkey"
    log.Debug("CheckHashkeySendMsgToDcrm.Run","send data",ss)
    p2pdcrm.SendToDcrmGroup(ss)
    //data := <-w.dcrmret
    data,cherr := GetChannelValue(ch_t,w.dcrmret)
    if cherr != nil {
	log.Debug("get w.dcrmret timeout.")
	var ret2 Err
	ret2.info = "get dcrm return result timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    log.Debug("CheckHashkeySendMsgToDcrm.Run","dcrm return data",data)
    
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_check_hashkey_res" {
	tmps := strings.Split(mm[0],"-")
	if cur_enode == tmps[0] {
	    if tmps[2] == "fail" {
		var ret2 Err
		ret2.info = tmps[3] 
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
	    }
	    
	    if tmps[2] == "true" {
		res := RpcDcrmRes{ret:tmps[2],err:nil}
		ch <- res
	    }
	}
    }

    return true
}
////////////////////////////////////////

type RpcDcrmRes struct {
    ret string
    err error
}

type RpcReq struct {
    rpcdata WorkReq
    ch chan interface{}
}

/////non dcrm///

func InitNonDcrmChan() {
    non_dcrm_workers = make([]RpcReqNonDcrmWorker,RpcMaxNonDcrmWorker)
    RpcReqNonDcrmQueue = make(chan RpcReq,RpcMaxNonDcrmQueue)
    reqdispatcher := NewReqNonDcrmDispatcher(RpcMaxNonDcrmWorker)
    reqdispatcher.Run()
}

type ReqNonDcrmDispatcher struct {
    // A pool of workers channels that are registered with the dispatcher
    WorkerPool chan chan RpcReq
}

func NewReqNonDcrmDispatcher(maxWorkers int) *ReqNonDcrmDispatcher {
    pool := make(chan chan RpcReq, maxWorkers)
    return &ReqNonDcrmDispatcher{WorkerPool: pool}
}

func (d *ReqNonDcrmDispatcher) Run() {
// starting n number of workers
    for i := 0; i < RpcMaxNonDcrmWorker; i++ {
	worker := NewRpcReqNonDcrmWorker(d.WorkerPool)
	worker.id = i
	non_dcrm_workers[i] = worker
	worker.Start()
    }

    go d.dispatch()
}

func (d *ReqNonDcrmDispatcher) dispatch() {
    for {
	select {
	    case req := <-RpcReqNonDcrmQueue:
	    // a job request has been received
	    go func(req RpcReq) {
		// try to obtain a worker job channel that is available.
		// this will block until a worker is idle
		reqChannel := <-d.WorkerPool

		// dispatch the job to the worker job channel
		reqChannel <- req
	    }(req)
	}
    }
}

func NewRpcReqNonDcrmWorker(workerPool chan chan RpcReq) RpcReqNonDcrmWorker {
    return RpcReqNonDcrmWorker{
    RpcReqWorkerPool: workerPool,
    RpcReqChannel: make(chan RpcReq),
    rpcquit:       make(chan bool),
    dcrmret:	make(chan string,1),
    ch:		   make(chan interface{})}
}

type RpcReqNonDcrmWorker struct {
    RpcReqWorkerPool  chan chan RpcReq
    RpcReqChannel  chan RpcReq
    rpcquit        chan bool

    id int

    ch chan interface{}
    dcrmret chan string
}

func (w RpcReqNonDcrmWorker) Start() {
    go func() {

	for {

	    // register the current worker into the worker queue.
	    w.RpcReqWorkerPool <- w.RpcReqChannel
	    select {
		    case req := <-w.RpcReqChannel:
			    req.rpcdata.Run(w.id,req.ch)

		    case <-w.rpcquit:
			// we have received a signal to stop
			    return
		}
	}
    }()
}

func (w RpcReqNonDcrmWorker) Stop() {
    go func() {
	w.rpcquit <- true
    }()
}

///////dcrm/////////

func getworkerid(msgprex string,enode string) int {//fun-e-xx-i-enode1-j-enode2-k
    
    prexs := strings.Split(msgprex,"-")
    if len(prexs) < 3 {
	return -1
    }

    s := prexs[:3]
    prex := strings.Join(s,"-")
    wid,exsit := types.GetDcrmRpcWorkersDataKReady(prex)
    if exsit == false {
	return -1
    }

    id,_ := strconv.Atoi(wid)
    return id

    msgs := strings.Split(msgprex,"-")
    for k,ens := range msgs {
	if ens == enode && k != 1 {
	    ret,_ := strconv.Atoi(msgs[k+1])
	    return ret
	}
	if ens == enode && k == 1 {
	    ret,_ := strconv.Atoi(msgs[3])
	    return ret
	}
    }

    return -1
}

type NodeWorkId struct {
    enode string
    workid int
}

//rpc-req
type ReqDispatcher struct {
    // A pool of workers channels that are registered with the dispatcher
    WorkerPool chan chan RpcReq
}

type RpcReqWorker struct {
    RpcReqWorkerPool  chan chan RpcReq
    RpcReqChannel  chan RpcReq
    rpcquit        chan bool

    id int
    groupnodes chan string
    msg_share1 chan string
    bshare1 chan bool

    dcrmres chan string
    bdcrmres chan bool
    
    lockout_dcrmres chan string
    lockout_bdcrmres chan bool
    //
    msg_c1 chan string
    msg_kc chan string
    msg_mkg chan string
    msg_mkw chan string
    msg_delta1 chan string
    msg_d1_1 chan string
    msg_d1_2 chan string
    msg_d1_3 chan string
    msg_d1_4 chan string
    msg_pai1 chan string
    bc1 chan bool
    bmkg chan bool
    bmkw chan bool
    bdelta1 chan bool
    bd1_1 chan bool
    bd1_2 chan bool
    bd1_3 chan bool
    bd1_4 chan bool
    bpai1 chan bool
    
    bidsready chan bool
    brealstartdcrm chan bool
    brealstartvalidate chan bool
    ch_nodeworkid chan NodeWorkId

    //confirmaddr
    txhash_conaddr chan string 
    hashkey chan string
    //liloreqaddr
    txhash_reqaddr chan string 
    fusionaddr chan string
    lilotx chan string

    //lockout
    txhash_lockout chan string
    fusionfrom chan string
    dcrmfrom chan string
    realfusionfrom chan string
    realdcrmfrom chan string
    lockoutto chan string
    amount chan string

    //reqaddr
    msgprex chan string
    pub chan string
    coint chan string

    //sign
    sig chan string
    txhash chan string
    dcrmaddr chan string

    //txhash validate
    tx chan string
    lockinaddr chan string
    //hashkey chan string
    msg_txvalidate chan string
    btxvalidate chan bool

    msg_c chan string
    msg_c11 chan string
    msg_d11_1 chan string
    msg_s1 chan string
    msg_ss1 chan string
    msg_d11_2 chan string
    msg_d11_3 chan string
    msg_d11_4 chan string
    msg_d11_5 chan string
    msg_d11_6 chan string
    msg_pai11 chan string
    msg_c21 chan string
    msg_d21_1 chan string
    msg_d21_2 chan string
    msg_d21_3 chan string
    msg_d21_4 chan string
    msg_pai21 chan string
    msg_paiw chan string
    msg_paienc chan string
    msg_encxshare chan string

    bkc chan bool
    bs1 chan bool
    bss1 chan bool
    bc11 chan bool
    bd11_1 chan bool
    bd11_2 chan bool
    bd11_3 chan bool
    bd11_4 chan bool
    bd11_5 chan bool
    bd11_6 chan bool
    bpai11 chan bool
    bc21 chan bool
    bd21_1 chan bool
    bd21_2 chan bool
    bd21_3 chan bool
    bd21_4 chan bool
    bpai21 chan bool
    bpaiw chan bool
    bpaienc chan bool
    bencxshare chan bool

    //
    encXShare chan string
    pkx chan string
    pky chan string
    save chan string
}

//workers,RpcMaxWorker,RpcReqWorker,RpcReqQueue,RpcMaxQueue,ReqDispatcher
func InitChan() {
    workers = make([]RpcReqWorker,RpcMaxWorker)
    RpcReqQueue = make(chan RpcReq,RpcMaxQueue)
    reqdispatcher := NewReqDispatcher(RpcMaxWorker)
    reqdispatcher.Run()
}

func NewReqDispatcher(maxWorkers int) *ReqDispatcher {
    pool := make(chan chan RpcReq, maxWorkers)
    return &ReqDispatcher{WorkerPool: pool}
}

func (d *ReqDispatcher) Run() {
// starting n number of workers
    for i := 0; i < RpcMaxWorker; i++ {
	worker := NewRpcReqWorker(d.WorkerPool)
	worker.id = i
	workers[i] = worker
	worker.Start()
    }

    go d.dispatch()
}

func (d *ReqDispatcher) dispatch() {
    for {
	select {
	    case req := <-RpcReqQueue:
	    // a job request has been received
	    go func(req RpcReq) {
		// try to obtain a worker job channel that is available.
		// this will block until a worker is idle
		reqChannel := <-d.WorkerPool

		// dispatch the job to the worker job channel
		reqChannel <- req
	    }(req)
	}
    }
}

func NewRpcReqWorker(workerPool chan chan RpcReq) RpcReqWorker {
    return RpcReqWorker{
    RpcReqWorkerPool: workerPool,
    RpcReqChannel: make(chan RpcReq),
    rpcquit:       make(chan bool),
    groupnodes:make(chan string,1),
    dcrmres:make(chan string,NodeCnt-1),
    bdcrmres:make(chan bool,1),
    lockout_dcrmres:make(chan string,NodeCnt-1),
    lockout_bdcrmres:make(chan bool,1),
    msg_share1:make(chan string,NodeCnt-1),
    bshare1:make(chan bool,1),
    msg_c1:make(chan string,NodeCnt-1),
    msg_d1_1:make(chan string,NodeCnt-1),
    msg_d1_2:make(chan string,NodeCnt-1),
    msg_d1_3:make(chan string,NodeCnt-1),
    msg_d1_4:make(chan string,NodeCnt-1),
    msg_pai1:make(chan string,NodeCnt-1),
    msg_c11:make(chan string,NodeCnt-1),
    msg_kc:make(chan string,NodeCnt-1),
    msg_mkg:make(chan string,NodeCnt-1),
    msg_mkw:make(chan string,NodeCnt-1),
    msg_delta1:make(chan string,NodeCnt-1),
    msg_d11_1:make(chan string,NodeCnt-1),
    msg_s1:make(chan string,NodeCnt-1),
    msg_ss1:make(chan string,NodeCnt-1),
    msg_d11_2:make(chan string,NodeCnt-1),
    msg_d11_3:make(chan string,NodeCnt-1),
    msg_d11_4:make(chan string,NodeCnt-1),
    msg_d11_5:make(chan string,NodeCnt-1),
    msg_d11_6:make(chan string,NodeCnt-1),
    msg_pai11:make(chan string,NodeCnt-1),
    msg_c21:make(chan string,NodeCnt-1),
    msg_d21_1:make(chan string,NodeCnt-1),
    msg_d21_2:make(chan string,NodeCnt-1),
    msg_d21_3:make(chan string,NodeCnt-1),
    msg_d21_4:make(chan string,NodeCnt-1),
    msg_pai21:make(chan string,NodeCnt-1),
    msg_paiw:make(chan string,NodeCnt-1),
    msg_paienc:make(chan string,NodeCnt-1),
    msg_encxshare:make(chan string,NodeCnt-1),
    msg_txvalidate:make(chan string,NodeCnt-1),
    bidsready:make(chan bool,1),
    brealstartdcrm:make(chan bool,1),
    brealstartvalidate:make(chan bool,1),
    txhash_conaddr:make(chan string,1),
    //hashkey:make(chan string,1),
    lockinaddr:make(chan string,1),
    hashkey:make(chan string,1),
    txhash_reqaddr:make(chan string,1),
    lilotx:make(chan string,1),
    txhash_lockout:make(chan string,1),
    fusionfrom:make(chan string,1),
    dcrmfrom:make(chan string,1),
    realfusionfrom:make(chan string,1),
    realdcrmfrom:make(chan string,1),
    lockoutto:make(chan string,1),
    amount:make(chan string,1),
    fusionaddr:make(chan string,1),
    msgprex:make(chan string,1),
    pub:make(chan string,1),
    coint:make(chan string,1),
    tx:make(chan string,1),
    sig:make(chan string,1),
    txhash:make(chan string,1),
    dcrmaddr:make(chan string,1),
    ch_nodeworkid: make(chan NodeWorkId,NodeCnt-1),
    encXShare:make(chan string,1),
    pkx:make(chan string,1),
    pky:make(chan string,1),
    save:make(chan string,1),
    bc1:make(chan bool,1),
    bd1_1:make(chan bool,1),
    bd1_2:make(chan bool,1),
    bd1_3:make(chan bool,1),
    bd1_4:make(chan bool,1),
    bc11:make(chan bool,1),
    bkc:make(chan bool,1),
    bs1:make(chan bool,1),
    bss1:make(chan bool,1),
    bmkg:make(chan bool,1),
    bmkw:make(chan bool,1),
    bdelta1:make(chan bool,1),
    bd11_1:make(chan bool,1),
    bd11_2:make(chan bool,1),
    bd11_3:make(chan bool,1),
    bd11_4:make(chan bool,1),
    bd11_5:make(chan bool,1),
    bd11_6:make(chan bool,1),
    bpai11:make(chan bool,1),
    btxvalidate:make(chan bool,1),
    bc21:make(chan bool,1),
    bd21_1:make(chan bool,1),
    bd21_2:make(chan bool,1),
    bd21_3:make(chan bool,1),
    bd21_4:make(chan bool,1),
    bpai21:make(chan bool,1),
    bpaiw:make(chan bool,1),
    bpaienc:make(chan bool,1),
    bencxshare:make(chan bool,1),
    bpai1:make(chan bool,1)}
}

func (w RpcReqWorker) Start() {
    go func() {

	for {

	    // register the current worker into the worker queue.
	    w.RpcReqWorkerPool <- w.RpcReqChannel
	    select {
		    case req := <-w.RpcReqChannel:
			    req.rpcdata.Run(w.id,req.ch)

		    case <-w.rpcquit:
			// we have received a signal to stop
			    return
		}
	}
    }()
}

func (w RpcReqWorker) Stop() {
    go func() {
	w.rpcquit <- true
    }()
}
//rpc-req

//////////////////////////////////////

func init(){
	discover.RegisterSendCallback(DispenseSplitPrivKey)
	p2pdcrm.RegisterRecvCallback(call)
	p2pdcrm.RegisterCallback(call)
	p2pdcrm.RegisterDcrmCallback(dcrmcall)
	p2pdcrm.RegisterDcrmRetCallback(dcrmret)
	
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	log.Root().SetHandler(glogger)

	erc20_client = nil
	BTC_BLOCK_CONFIRMS = 1
	BTC_DEFAULT_FEE = 0.0005
	ETH_DEFAULT_FEE,_ = new(big.Int).SetString("10000000000000000",10)
	rpcs,_ = new(big.Int).SetString("0",10)
}

func InitP2pParams() {
    //cur_enode = p2pdcrm.GetSelfID().String()
    //NodeCnt, _ = p2pdcrm.GetGroup()
    //enode_cnts,_ = p2pdcrm.GetEnodes()
}

func dcrmret(msg interface{}) {

    data := fmt.Sprintf("%s",msg)
    log.Debug("dcrmret","receive data",data)
    if data == "" {
	return 
    }
    
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_req_dcrmaddr_res" {
	tmps := strings.Split(mm[0],"-")
	//log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
    if len(mm) == 2 && mm[1] == "rpc_confirm_dcrmaddr_res" {
	tmps := strings.Split(mm[0],"-")
	//log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
    if len(mm) == 2 && mm[1] == "rpc_lockin_res" {
	tmps := strings.Split(mm[0],"-")
	//log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
    if len(mm) == 2 && mm[1] == "rpc_lockout_res" {
	tmps := strings.Split(mm[0],"-")
	//log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
    if len(mm) == 2 && mm[1] == "rpc_check_hashkey_res" {
	tmps := strings.Split(mm[0],"-")
	//log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
}

func dcrmcall(msg interface{}) <-chan string {

    log.Debug("dcrmcall","current node",cur_enode,"get msg",msg)
    ch := make(chan string, 1)
    data := fmt.Sprintf("%s",msg)
    mm := strings.Split(data,msgtypesep)

    if len(mm) == 2 && mm[1] == "rpc_confirm_dcrmaddr" {
	tmps := strings.Split(mm[0],"-")
	v := DcrmConfirmAddr{Txhash:tmps[1],Tx:tmps[2],FusionAddr:tmps[3],DcrmAddr:tmps[4],Hashkey:tmps[5],Cointype:tmps[6]}
	_,err := Dcrm_ConfirmAddr(&v)
	if err != nil {
	ss := tmps[0] + "-" + tmps[7] + "-" + "fail" + "-" + err.Error() + msgtypesep + "rpc_confirm_dcrmaddr_res"

	ch <- ss 
	return ch
    }
   
	//ss:  enode-wid-addr || rpc_confirm_dcrmaddr_res
	ss := tmps[0] + "-" + tmps[7] + "-" + "true" + msgtypesep + "rpc_confirm_dcrmaddr_res"
	ch <- ss 
	return ch
    }

    if len(mm) == 2 && mm[1] == "rpc_req_dcrmaddr" {
	tmps := strings.Split(mm[0],"-")
	has,da,err := IsFusionAccountExsitDcrmAddr(tmps[1],tmps[3],"")
	if err == nil && has == true {
	    log.Debug("==========dcrmcall,req add fail.========")
	    ss := tmps[0] + "-" + tmps[4] + "-" + "fail" + "-" + "the account has request dcrm address already.the dcrm address is:" + da + msgtypesep + "rpc_req_dcrmaddr_res"  //???? "-" == error

	    ch <- ss 
	    //ss := tmps[0] + "-" + tmps[4] + "-" + da + msgtypesep + "rpc_req_dcrmaddr_res"
	    //ch <- ss 
	    return ch
	}

	v := DcrmLiLoReqAddress{Fusionaddr:tmps[1],Pub:tmps[2],Cointype:tmps[3]}
	addr,err := Dcrm_LiLoReqAddress(&v)
	//log.Debug("================dcrmcall,","ret addr",addr,"","==================")
	if err != nil {
	    log.Debug("==========dcrmcall,req add fail.========")
	    ss := tmps[0] + "-" + tmps[4] + "-" + "fail" + "-" + err.Error() + msgtypesep + "rpc_req_dcrmaddr_res"  //???? "-" == error

	    ch <- ss 
	    return ch
	}
   
	//log.Debug("dcrmcall,req add success","add",addr)
	//ss:  enode-wid-addr || rpc_req_dcrmaddr_res
	ss := tmps[0] + "-" + tmps[4] + "-" + addr + msgtypesep + "rpc_req_dcrmaddr_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    } 

    if len(mm) == 2 && mm[1] == "rpc_lockin" {
	tmps := strings.Split(mm[0],"-")
	v := DcrmLockin{Tx:tmps[2],LockinAddr:tmps[7],Hashkey:tmps[4],RealDcrmFrom:tmps[8]}
	_,err := Validate_Txhash(&v)
	if err != nil {
	ss := tmps[0] + "-" + tmps[9] + "-" + "fail" + "-" + err.Error() + msgtypesep + "rpc_lockin_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }
   
	//ss:  enode-wid-true || rpc_lockin_res
	ss := tmps[0] + "-" + tmps[9] + "-" + "true" + msgtypesep + "rpc_lockin_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }

    if len(mm) == 2 && mm[1] == "rpc_check_hashkey" {
	tmps := strings.Split(mm[0],"-")
	has,err := IsHashkeyExsitInLocalDB(tmps[3])
	if err != nil {
	ss := tmps[0] + "-" + tmps[4] + "-" + "fail" + "-" + err.Error() + msgtypesep + "rpc_check_hashkey_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }
	if has == true {
	ss := tmps[0] + "-" + tmps[4] + "-" + "fail" + "-" + "error: the dcrmaddr has lockin already." + msgtypesep + "rpc_check_hashkey_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }
   
	ss := tmps[0] + "-" + tmps[4] + "-" + "true" + msgtypesep + "rpc_check_hashkey_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }

    if len(mm) == 2 && mm[1] == "rpc_lockout" {
	tmps := strings.Split(mm[0],"-")
	//bug
	val,ok := GetLockoutInfoFromLocalDB(tmps[1])
	if ok == nil && val != "" {
	    types.SetDcrmValidateData(tmps[1],val)
	    ss := tmps[0] + "-" + tmps[10] + "-" + val + msgtypesep + "rpc_lockout_res"
	    ch <- ss 
	    return ch
	}
	//
	
	/////
	realfusionfrom,realdcrmfrom,err := ChooseRealFusionAccountForLockout(tmps[8],tmps[7],tmps[9])
	if err != nil {
	    log.Debug("============dcrmcall,get real fusion/dcrm from fail.===========")
	    ss := tmps[0] + "-" + tmps[10] + "-" + "fail" + "-" + err.Error() + msgtypesep + "rpc_lockout_res"
	    ch <- ss 
	    return ch
	}

	//real from
	if IsValidFusionAddr(realfusionfrom) == false {
	    log.Debug("============dcrmcall,validate real fusion from fail.===========")
	    ss := tmps[0] + "-" + tmps[10] + "-" + "fail" + "-" + "can not get suitable fusion from account" + msgtypesep + "rpc_lockout_res"
	    ch <- ss 
	    return ch
	}
	if IsValidDcrmAddr(realdcrmfrom,tmps[9]) == false {
	    log.Debug("============dcrmcall,validate real dcrm from fail.===========")
	    ss := tmps[0] + "-" + tmps[10] + "-" + "fail" +  "-" + "can not get suitable dcrm from addr" + msgtypesep + "rpc_lockout_res"
	    ch <- ss 
	    return ch
	}
	/////

	log.Debug("============dcrmcall,","get real fusion from",realfusionfrom,"get real dcrm from",realdcrmfrom,"","===========")
	v := DcrmLockout{Txhash:tmps[1],Tx:tmps[2],FusionFrom:tmps[3],DcrmFrom:tmps[4],RealFusionFrom:realfusionfrom,RealDcrmFrom:realdcrmfrom,Lockoutto:tmps[7],Value:tmps[8],Cointype:tmps[9]}
	retva,err := Validate_Lockout(&v)
	if err != nil {
	ss := tmps[0] + "-" + tmps[10] + "-" + "fail" + "-" + err.Error() + msgtypesep + "rpc_lockout_res"
	ch <- ss 
	return ch
    }
 
	ss := tmps[0] + "-" + tmps[10] + "-" + retva + msgtypesep + "rpc_lockout_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }

    return ch
}

func call(msg interface{}) {
	SetUpMsgList(msg.(string))
}

var parts = make(map[int]string)
func receiveSplitKey(msg interface{}){
	log.Debug("==========receiveSplitKey==========")
	log.Debug("","get msg", msg)
	cur_enode = p2pdcrm.GetSelfID().String()
	log.Debug("","cur_enode", cur_enode)
	head := strings.Split(msg.(string), ":")[0]
	body := strings.Split(msg.(string), ":")[1]
	if a := strings.Split(body, "#"); len(a) > 1 {
		tmp2 = a[0]
		body = a[1]
	}
	p, _ := strconv.Atoi(strings.Split(head, "dcrmslash")[0])
	total, _ := strconv.Atoi(strings.Split(head, "dcrmslash")[1])
	parts[p] = body
	if len(parts) == total {
		var c string = ""
		for i := 1; i <= total; i++ {
			c += parts[i]
		}
		peerscount, _ := p2pdcrm.GetGroup()
		Init(tmp2,c,peerscount)
	}
}

func Init(tmp string,c string,nodecnt int) {
    if init_times >= 1 {
	    return
    }

   NodeCnt = nodecnt
   enode_cnts = nodecnt //bug
    log.Debug("=============Init,","the node count",NodeCnt,"","===========")
    GetEnodesInfo()  
    InitChan()
    init_times = 1
}

//for eth 
type RPCTransaction struct {
	BlockHash        common.Hash     `json:"blockHash"`
	BlockNumber      *hexutil.Big    `json:"blockNumber"`
	From             common.Address  `json:"from"`
	Gas              hexutil.Uint64  `json:"gas"`
	GasPrice         *hexutil.Big    `json:"gasPrice"`
	Hash             common.Hash     `json:"hash"`
	Input            hexutil.Bytes   `json:"input"`
	Nonce            hexutil.Uint64  `json:"nonce"`
	To               *common.Address `json:"to"`
	TransactionIndex hexutil.Uint    `json:"transactionIndex"`
	Value            *hexutil.Big    `json:"value"`
	V                *hexutil.Big    `json:"v"`
	R                *hexutil.Big    `json:"r"`
	S                *hexutil.Big    `json:"s"`
}

/////////////////////for btc main chain
type Scriptparm struct {
    Asm string
    Hex string
    ReqSigs int64
    Type string
    Addresses []string
}

type Voutparm struct {
    Value float64
    N int64
    ScriptPubKey Scriptparm
}

//for btc main chain noinputs
type BtcTxResInfoNoInputs struct {
    Result GetTransactionResultNoInputs
    Error error 
    Id int
}

type VinparmNoInputs struct {
    Coinbase string
    Sequence int64
}

type GetTransactionResultNoInputs struct {
    Txid string
    Hash string
    Version int64
    Size int64
    Vsize int64
    Weight int64
    Locktime int64
    Vin []VinparmNoInputs
    Vout []Voutparm
    Hex string
    Blockhash string
    Confirmations   int64
    Time            int64
    BlockTime            int64
}

//for btc main chain noinputs
type BtcTxResInfo struct {
    Result GetTransactionResult
    Error error 
    Id int
}

type ScriptSigParam struct {
    Asm string 
    Hex string
}

type Vinparm struct {
    Txid string
    Vout int64
    ScriptSig ScriptSigParam
    Sequence int64
}

type GetTransactionResult struct {
    Txid string
    Hash string
    Version int64
    Size int64
    Vsize int64
    Weight int64
    Locktime int64
    Vin []Vinparm
    Vout []Voutparm
    Hex string
    Blockhash string
    Confirmations   int64
    Time            int64
    BlockTime            int64
}

//////////////////////////

func ValidBTCTx(returnJson string,txhash string,realdcrmfrom string,realdcrmto string,value string,islockout bool,ch chan interface{}) {

    if len(returnJson) == 0 {
	var ret2 Err
	ret2.info = "get return json fail."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    //TODO  realdcrmfrom ???

    var btcres_noinputs BtcTxResInfoNoInputs
    json.Unmarshal([]byte(returnJson), &btcres_noinputs)
    log.Debug("===============ValidBTCTx,","btcres_noinputs",btcres_noinputs,"","============")
    if btcres_noinputs.Result.Vout != nil && btcres_noinputs.Result.Txid == txhash {
	log.Debug("=================ValidBTCTx,btcres_noinputs.Result.Vout != nil========")
	vparam := btcres_noinputs.Result.Vout
	for _,vp := range vparam {
	    spub := vp.ScriptPubKey
	    sas := spub.Addresses
	    for _,sa := range sas {
		if sa == realdcrmto {
		    log.Debug("======to addr equal.========")
		    amount := vp.Value*100000000
		    log.Debug("============ValidBTCTx,","vp.value",vp.Value,"","============")
		    //vvtmp := fmt.Sprintf("%v",amount)
		    //log.Debug("========ValidBTCTx,","vvtmp",vvtmp,"","=============")
		    vv := strconv.FormatFloat(amount, 'f', 0, 64)
		    log.Debug("========ValidBTCTx,","vv",vv,"","=============")
		    log.Debug("========ValidBTCTx,","value",value,"","=============")
		    if islockout {
			log.Debug("============ValidBTCTx,is lockout,","Confirmations",btcres_noinputs.Result.Confirmations,"","============")
			if btcres_noinputs.Result.Confirmations >= BTC_BLOCK_CONFIRMS {
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			}

			b,ee := GetLockoutConfirmations(txhash)
			if b && ee == nil {
			    log.Debug("========ValidBTCTx,lockout tx is confirmed.============")
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			} else if ee != nil {
			    res := RpcDcrmRes{ret:"",err:ee}
			    ch <- res
			    return 
			}

			var ret2 Err
			ret2.info = "get btc transaction fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    } else {
			log.Debug("============ValidBTCTx,","Confirmations",btcres_noinputs.Result.Confirmations,"","============")
			vvn,_ := new(big.Int).SetString(vv,10)
			van,_ := new(big.Int).SetString(value,10)
			if vvn != nil && van != nil && vvn.Cmp(van) == 0 && btcres_noinputs.Result.Confirmations >= BTC_BLOCK_CONFIRMS {
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			} 
			
			b,ee := GetLockoutConfirmations(txhash)
			if vvn != nil && van != nil && vvn.Cmp(van) == 0 && b && ee == nil {
			    log.Debug("========ValidBTCTx,lockin tx is confirmed.============")
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			} else if ee != nil {
			    res := RpcDcrmRes{ret:"",err:ee}
			    ch <- res
			    return 
			}

			if vvn != nil && van != nil && vvn.Cmp(van) == 0 {
			    var ret2 Err
			    ret2.info = "get btc transaction fail."
			    res := RpcDcrmRes{ret:"",err:ret2}
			    ch <- res
			    return
			} else {
			    var ret2 Err
			    ret2.info = "outside tx fail."
			    res := RpcDcrmRes{ret:"",err:ret2}
			    ch <- res
			    return
			}
		    }

		}
	    }
	}
    }
    
    var btcres BtcTxResInfo
    json.Unmarshal([]byte(returnJson), &btcres)
    log.Debug("===============ValidBTCTx,","btcres",btcres,"","============")
    if btcres.Result.Vout != nil && btcres.Result.Txid == txhash {
	log.Debug("=================ValidBTCTx,btcres.Result.Vout != nil========")
	vparam := btcres.Result.Vout
	for _,vp := range vparam {
	    spub := vp.ScriptPubKey
	    sas := spub.Addresses
	    for _,sa := range sas {
		if sa == realdcrmto {
		    log.Debug("======to addr equal.========")
		    amount := vp.Value*100000000
		    log.Debug("============ValidBTCTx,","vp.value",vp.Value,"","============")
		    //vvtmp := fmt.Sprintf("%v",amount)
		    //log.Debug("========ValidBTCTx,","vvtmp",vvtmp,"","=============")
		    vv := strconv.FormatFloat(amount, 'f', 0, 64)
		    if islockout {
			log.Debug("============ValidBTCTx,is lockout,","Confirmations",btcres.Result.Confirmations,"","============")
			if btcres.Result.Confirmations >= BTC_BLOCK_CONFIRMS {
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			}
			
			b,ee := GetLockoutConfirmations(txhash)
			if b && ee == nil {
			    log.Debug("========ValidBTCTx,lockout tx is confirmed.============")
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			} else if ee != nil {
			    res := RpcDcrmRes{ret:"",err:ee}
			    ch <- res
			    return
			}

			var ret2 Err
			ret2.info = "get btc transaction fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    } else {
			log.Debug("============ValidBTCTx,","Confirmations",btcres.Result.Confirmations,"","============")
			vvn,_ := new(big.Int).SetString(vv,10)
			van,_ := new(big.Int).SetString(value,10)
			if vvn != nil && van != nil && vvn.Cmp(van) == 0 && btcres.Result.Confirmations >= BTC_BLOCK_CONFIRMS {
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			} 
			
			b,ee := GetLockoutConfirmations(txhash)
			if vvn != nil && van != nil && vvn.Cmp(van) == 0 && b && ee == nil {
			    log.Debug("========ValidBTCTx,lockout tx is confirmed.============")
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			} else if ee != nil {
			    res := RpcDcrmRes{ret:"",err:ee}
			    ch <- res
			    return
			}

			if vvn != nil && van != nil && vvn.Cmp(van) == 0 {
			    var ret2 Err
			    ret2.info = "get btc transaction fail."
			    res := RpcDcrmRes{ret:"",err:ret2}
			    ch <- res
			    return
			} else {
			    var ret2 Err
			    ret2.info = "outside tx fail."
			    res := RpcDcrmRes{ret:"",err:ret2}
			    ch <- res
			    return
			}
		    }
		}
	    }
	}
    }

    log.Debug("=================ValidBTCTx,return is fail.========")
    var ret2 Err
    ret2.info = "validate btc tx fail."
    res := RpcDcrmRes{ret:"",err:ret2}
    ch <- res
    return
}

func GetLockoutConfirmations(txhash string) (bool,error) {
    if txhash == "" {
	return false,errors.New("param error.")
    }

    reqJson2 := "{\"jsonrpc\":\"1.0\",\"method\":\"getrawtransaction\",\"params\":[\"" + txhash + "\"" + "," + "true" + "],\"id\":1}";
    s := "http://"
    s += SERVER_HOST
    s += ":"
    s += strconv.Itoa(SERVER_PORT)
    ret := DoCurlRequest(s,"",reqJson2)
    log.Debug("=============GetLockoutConfirmations,","curl ret",ret,"","=============")
    
    var btcres_noinputs BtcTxResInfoNoInputs
    ok := json.Unmarshal([]byte(ret), &btcres_noinputs)
    log.Debug("=============GetLockoutConfirmations,","ok",ok,"","=============")
    if ok == nil && btcres_noinputs.Result.Confirmations >= BTC_BLOCK_CONFIRMS {
	return true,nil
    }
    var btcres BtcTxResInfo
    ok = json.Unmarshal([]byte(ret), &btcres)
    log.Debug("=============GetLockoutConfirmations,","ok",ok,"","=============")
    if ok == nil && btcres.Result.Confirmations >= BTC_BLOCK_CONFIRMS {
	return true,nil
    }

    if ok != nil {
	return false,errors.New("outside tx fail.") //real fail.
    }

    return false,nil
}

func DoCurlRequest (url, api, data string) string {
    var err error
    cmd := exec.Command("/bin/sh")
    in := bytes.NewBuffer(nil)
    cmd.Stdin = in
    var out bytes.Buffer
    cmd.Stdout = &out
    go func() {
	    s := "curl --user "
	    s += USER
	    s += ":"
	    s += PASSWD
	    s += " -H 'content-type:text/plain;' "
	    str := s + url + "/" + api
	    if len(data) > 0 {
		    str = str + " --data-binary " + "'" + data + "'"
	    }
	    in.WriteString(str)
    }()
    err = cmd.Start()
    if err != nil {
	    //log.Fatal(err)
	    log.Debug(err.Error())
    }
    //log.Debug(cmd.Args)
    err = cmd.Wait()
    if err != nil {
	    log.Debug("Command finished with error: %v", err)
    }
    return out.String()
}

func validate_txhash(msgprex string,tx string,lockinaddr string,hashkey string,realdcrmfrom string,ch chan interface{}) {
    log.Debug("===============validate_txhash===========")
    curs := strings.Split(msgprex,"-")
    //log.Debug("===============validate_txhash,","msgprex",msgprex,"","==================")
    if len(curs) >= 2 && strings.EqualFold(curs[1],cur_enode) == false { //bug
	log.Debug("===============validate_txhash,nothing need to do.==================")
	var ret2 Err
	ret2.info = "nothing to do."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    //=======================================
    xxx := strings.Split(tx,"-")
    if len(xxx) > 0 && strings.EqualFold(xxx[0],"xxx") {
	var cointype string
	var realdcrmto string
	var lockinvalue string
	cointype = xxx[2] 
	realdcrmto = lockinaddr
	lockinvalue = xxx[1]
	if realdcrmfrom == "" {
	    log.Debug("===============validate_txhash,choose real fusion account fail.==================")
	    var ret2 Err
	    ret2.info = "choose real fusion account fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}

	if strings.EqualFold(cointype,"BTC") == true {
	    rpcClient, err := NewClient(SERVER_HOST, SERVER_PORT, USER, PASSWD, USESSL)
	    if err != nil {
		    log.Debug("=============validate_txhash,new client fail.========")
		    var ret2 Err
		    ret2.info = "new client fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
	    }
	    reqJson := "{\"method\":\"getrawtransaction\",\"params\":[\"" + string(hashkey) + "\"" + "," + "true" + "],\"id\":1}";
	    //reqJson := "{\"method\":\"decoderawtransaction\",\"params\":[\"" + string(hashkey) + "\"" + "," + "true" + "],\"id\":1}";

	    //timeout TODO
	    var returnJson string
	    returnJson, err2 := rpcClient.Send(reqJson)
	    log.Debug("=============validate_txhash,","return Json data",returnJson,"","=============")
	    if err2 != nil {
		    log.Debug("=============validate_txhash,send rpc fail.========")
		    var ret2 Err
		    ret2.info = "send rpc fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
	    }

	    ////
	    if returnJson == "" {
		log.Debug("=============validate_txhash,get btc transaction fail.========")
		var ret2 Err
		ret2.info = "get btc transaction fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }

	    ////
	    ValidBTCTx(returnJson,hashkey,realdcrmfrom,realdcrmto,xxx[1],true,ch) 
	    return
	}

	answer := "no_pass" 
	if strings.EqualFold(cointype,"ETH") == true || strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {

	    if strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
		client, err := rpc.Dial(ETH_SERVER)
		if err != nil {
			log.Debug("==============validate_txhash,eth rpc.Dial error.===========")
			var ret2 Err
			ret2.info = "eth rpc.Dial error."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var r *types.Receipt
		err = client.CallContext(ctx, &r, "eth_getTransactionReceipt", common.HexToHash(hashkey))
		if err != nil {
		    var ret2 Err
		    ret2.info = "get erc20 tx info fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}

		//bug
		log.Debug("===============validate_txhash,","receipt",r,"","=================")
		if r == nil {
		    var ret2 Err
		    ret2.info = "erc20 tx validate fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}
		//

		for _, logs := range r.Logs {
		    ercdata := new(big.Int).SetBytes(logs.Data)//string(logs.Data)
		    ercdatanum := fmt.Sprintf("%v",ercdata)
		    log.Debug("===============validate_txhash,","erc data",ercdatanum,"","=================")
		    for _,top := range logs.Topics {
			log.Debug("===============validate_txhash,","top",top.Hex(),"","=================")
			/////

			aa,_ := new(big.Int).SetString(top.Hex(),0)
			bb,_ := new(big.Int).SetString(realdcrmto,0)
			if lockinvalue == ercdatanum && aa.Cmp(bb) == 0 {
			    log.Debug("==============validate_txhash,erc validate pass.===========")
			    answer = "pass"
			    break
			}
		    }
		}
		
		if answer == "pass" {
		    log.Debug("==============validate_txhash,answer pass.===========")
		    res := RpcDcrmRes{ret:"true",err:nil}
		    ch <- res
		    return
		} 

		log.Debug("==============validate_txhash,answer no pass.===========")
		var ret2 Err
		ret2.info = "lockin validate fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }

	     client, err := rpc.Dial(ETH_SERVER)
	    if err != nil {
		    log.Debug("==============validate_txhash,eth rpc.Dial error.===========")
		    var ret2 Err
		    ret2.info = "eth rpc.Dial error."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
	    }

	    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	    defer cancel()

	    var result RPCTransaction

	    //timeout TODO
		err = client.CallContext(ctx, &result, "eth_getTransactionByHash",hashkey)
		if err != nil {
			log.Debug("===============validate_txhash,client call error.===========")
			var ret2 Err
			ret2.info = "client call error."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		}

		log.Debug("===============validate_txhash,","get BlockHash",result.BlockHash,"get BlockNumber",result.BlockNumber,"get From",result.From,"get Hash",result.Hash,"","===============")

		if result.To == nil {
		    log.Debug("===============validate_txhash,validate tx fail.===========")
		    var ret2 Err
		    ret2.info = "validate tx fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}

		////
		if result.From.Hex() == "" {
		    var ret2 Err
		    ret2.info = "get eth transaction fail."  //no confirmed
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}
		////

	    var from string
	    var to string
	    var value *big.Int 
	    var vv string
	    if strings.EqualFold(cointype,"ETH") == true {
		from = result.From.Hex()
		to = (*result.To).Hex()
		value, _ = new(big.Int).SetString(result.Value.String(), 0)
		vv = fmt.Sprintf("%v",value)
	    } 
	    
	    ////bug
	    var vvv string
	    vvv = xxx[1]
	    log.Debug("===============validate_txhash,","get to",to,"get value",vv,"real dcrm to",realdcrmto,"rpc value",vvv,"","===============")

	    if strings.EqualFold(from,realdcrmfrom) && vv == vvv && strings.EqualFold(to,realdcrmto) == true {
		answer = "pass"
	    }
	}

	if answer == "pass" {
	    res := RpcDcrmRes{ret:"true",err:nil}
	    ch <- res
	    return
	} 

	var ret2 Err
	ret2.info = "lockin validate fail."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res

	return
    }
    //=======================================

    signtx := new(types.Transaction)
    err := signtx.UnmarshalJSON([]byte(tx))
    if err != nil {
	log.Debug("===============validate_txhash,new transaction fail.==================")
	var ret2 Err
	ret2.info = "new transaction fail."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    payload := signtx.Data()
    m := strings.Split(string(payload),":")

    var cointype string
    var realdcrmto string
    var lockinvalue string
    
    if m[0] == "LOCKIN" {
	lockinvalue = m[2]
	cointype = m[3] 
	realdcrmto = lockinaddr
    }
    if m[0] == "LOCKOUT" {
	log.Debug("===============validate_txhash,it is lockout.===========")
	cointype = m[3]
	realdcrmto = m[1]
	
	log.Debug("===============validate_txhash,","real dcrm from",realdcrmfrom,"","=================")
	if realdcrmfrom == "" {
	    log.Debug("===============validate_txhash,choose real fusion account fail.==================")
	    var ret2 Err
	    ret2.info = "choose real fusion account fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
    }

    if strings.EqualFold(cointype,"BTC") == true {
	rpcClient, err := NewClient(SERVER_HOST, SERVER_PORT, USER, PASSWD, USESSL)
	if err != nil {
		log.Debug("=============validate_txhash,new client fail.========")
		var ret2 Err
		ret2.info = "new client fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	}

	reqJson := "{\"method\":\"getrawtransaction\",\"params\":[\"" + string(hashkey) + "\"" + "," + "true" + "],\"id\":1}";

	//timeout TODO
	var returnJson string
	returnJson, err2 := rpcClient.Send(reqJson)
	log.Debug("=============validate_txhash,","return Json data",returnJson,"","=============")
	if err2 != nil {
		log.Debug("=============validate_txhash,send rpc fail.========")
		var ret2 Err
		ret2.info = "send rpc fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	}

	////
	if returnJson == "" {
	    log.Debug("=============validate_txhash,get btc transaction fail.========")
	    var ret2 Err
	    ret2.info = "get btc transaction fail." //no confirmed
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
	////

	if m[0] == "LOCKIN" {
	    ValidBTCTx(returnJson,hashkey,realdcrmfrom,realdcrmto,lockinvalue,false,ch) 
	    return
	}
	if m[0] == "LOCKOUT" {
	    ValidBTCTx(returnJson,hashkey,realdcrmfrom,realdcrmto,m[2],true,ch) 
	    return
	}

    }

    answer := "no_pass" 
    if strings.EqualFold(cointype,"ETH") == true || strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {

	if strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
	    client, err := rpc.Dial(ETH_SERVER)
	    if err != nil {
		    log.Debug("==============validate_txhash,eth rpc.Dial error.===========")
		    var ret2 Err
		    ret2.info = "eth rpc.Dial error."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
	    }

	    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	    defer cancel()

	    var r *types.Receipt
	    err = client.CallContext(ctx, &r, "eth_getTransactionReceipt", common.HexToHash(hashkey))
	    if err != nil {
		var ret2 Err
		ret2.info = "get erc20 tx info fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }

	    //bug
	    log.Debug("===============validate_txhash,","receipt",r,"","=================")
	    if r == nil {
		var ret2 Err
		ret2.info = "erc20 tx validate fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }
	    //

	    for _, logs := range r.Logs {
		ercdata := new(big.Int).SetBytes(logs.Data)//string(logs.Data)
		ercdatanum := fmt.Sprintf("%v",ercdata)
		log.Debug("===============validate_txhash,","erc data",ercdatanum,"","=================")
		for _,top := range logs.Topics {
		    log.Debug("===============validate_txhash,","top",top.Hex(),"","=================")
		    //log.Debug("===============validate_txhash,","realdcrmto",realdcrmto,"","=================")
		    /////
		    aa,_ := new(big.Int).SetString(top.Hex(),0)
		    bb,_ := new(big.Int).SetString(realdcrmto,0)
		    if lockinvalue == ercdatanum && aa.Cmp(bb) == 0 {
			log.Debug("==============validate_txhash,erc validate pass.===========")
			answer = "pass"
			break
		    }
		}
	    }
	    
	    if answer == "pass" {
		log.Debug("==============validate_txhash,answer pass.===========")
		res := RpcDcrmRes{ret:"true",err:nil}
		ch <- res
		return
	    } 

	    log.Debug("==============validate_txhash,answer no pass.===========")
	    var ret2 Err
	    ret2.info = "lockin validate fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}

	 client, err := rpc.Dial(ETH_SERVER)
        if err != nil {
		log.Debug("==============validate_txhash,eth rpc.Dial error.===========")
		var ret2 Err
		ret2.info = "eth rpc.Dial error."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
        }

        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

	var result RPCTransaction

	//timeout TODO
	    err = client.CallContext(ctx, &result, "eth_getTransactionByHash",hashkey)
	    if err != nil {
		    log.Debug("===============validate_txhash,client call error.===========")
		    var ret2 Err
		    ret2.info = "client call error."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
	    }
//	    log.Debug("===============validate_txhash,","result",result,"","=================")

	    log.Debug("===============validate_txhash,","get BlockHash",result.BlockHash,"get BlockNumber",result.BlockNumber,"get From",result.From,"get Hash",result.Hash,"","===============")

	    //============================================
	    if result.To == nil {
		log.Debug("===============validate_txhash,validate tx fail.===========")
		var ret2 Err
		ret2.info = "validate tx fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }

	    ////
	    if result.From.Hex() == "" {
		var ret2 Err
		ret2.info = "get eth transaction fail."  //no confirmed
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }
	    ////

//	log.Debug("===============validate_txhash,ETH out of for loop.================",)

	var from string
	var to string
	var value *big.Int 
	var vv string
	if strings.EqualFold(cointype,"ETH") == true {
	    from = result.From.Hex()
	    to = (*result.To).Hex()
	    value, _ = new(big.Int).SetString(result.Value.String(), 0)
	    vv = fmt.Sprintf("%v",value)
	} 
	
	log.Debug("==========","m1",m[1],"m2",m[2],"m3",m[3],"","==============")
	////bug
	var vvv string
	if m[0] == "LOCKOUT" {
	    log.Debug("==========","vvv",vvv,"m1",m[1],"m2",m[2],"m3",m[3],"","==============")
	    vvv = m[2]//fmt.Sprintf("%v",signtx.Value())//string(signtx.Value().Bytes())
	} else {
	    vvv = lockinvalue//string(signtx.Value().Bytes())
	}
	log.Debug("===============validate_txhash,","get to",to,"get value",vv,"real dcrm to",realdcrmto,"rpc value",vvv,"","===============")

	if m[0] == "LOCKOUT" {
	    if strings.EqualFold(from,realdcrmfrom) && vv == vvv && strings.EqualFold(to,realdcrmto) == true {
		answer = "pass"
	    }
	} else if strings.EqualFold(to,realdcrmto) && vv == vvv {
	    fmt.Printf("===========m[0]!=LOCKOUT==============\n")
	    answer = "pass"
	}
    }

  //  log.Debug("===============validate_txhash,validate finish.================")

    if answer == "pass" {
	res := RpcDcrmRes{ret:"true",err:nil}
	ch <- res
	return
    } 

    var ret2 Err
    ret2.info = "lockin validate fail."
    res := RpcDcrmRes{ret:"",err:ret2}
    ch <- res
}

type SendRawTxRes struct {
    Hash common.Hash
    Err error
}

func IsInGroup() bool {
    cnt,enode := p2pdcrm.GetGroup()
    //log.Debug("=============IsInGroup,", "cnt", cnt, "enode", enode,"","==============")
    if cnt <= 0 || enode == "" {
	return false
    }

    //log.Debug("================IsInGroup start================")
    nodes := strings.Split(enode,sep2)
    for _,node := range nodes {
	node2, _ := discover.ParseNode(node)
	//log.Debug("=============IsInGroup,", "node",node, "node2",node2,"cur_enode",cur_enode,"node2.ID.String()",node2.ID.String(),"","==============")
	if node2.ID.String() == cur_enode {
	    return true
	}
    }

    //log.Debug("================IsInGroup end================")
    return false
}

func Validate_Txhash(wr WorkReq) (string,error) {

    log.Debug("=============Validate_Txhash =====================")
    //////////
    if IsInGroup() == false {
	log.Debug("=============Validate_Txhash,??? =====================")
	return "true",nil
    }
    //////////

    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    //ret := (<- rch).(RpcDcrmRes)
    ret,cherr := GetChannelValue(ch_t,rch)
    if cherr != nil {
	log.Debug("============Validate_Txhash,","get error",cherr.Error(),"","==============")
	return "",cherr 
    }
    return ret,cherr
}
//###############

		func GetEnodesInfo() {
		    enode_cnts,_ = p2pdcrm.GetEnodes()
		    NodeCnt = enode_cnts
		    cur_enode = p2pdcrm.GetSelfID().String()
		}

		//error type 1
		type Err struct {
			info  string
		}

		func (e Err) Error() string {
			return e.info
		}

		//=============================================

		func PathExists(path string) (bool, error) {
			_, err := os.Stat(path)
			if err == nil {
				return true, nil
			}
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}

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

		func dcrm_confirmaddr(msgprex string,txhash_conaddr string,tx string,fusionaddr string,dcrmaddr string,hashkey string,cointype string,ch chan interface{}) {	
		    GetEnodesInfo()
		    if strings.EqualFold(cointype,"ETH") == false && strings.EqualFold(cointype,"BTC") == false && strings.EqualFold(cointype,"GUSD") == false && strings.EqualFold(cointype,"BNB") == false && strings.EqualFold(cointype,"MKR") == false && strings.EqualFold(cointype,"HT") == false && strings.EqualFold(cointype,"BNT") == false {
			log.Debug("===========coin type is not supported.must be btc or eth.================")
			var ret2 Err
			ret2.info = "coin type is not supported."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    has,_,err := IsFusionAccountExsitDcrmAddr(fusionaddr,cointype,dcrmaddr)
		    if err == nil && has == true {
			log.Debug("the dcrm addr confirm validate success.")
			res := RpcDcrmRes{ret:"true",err:nil}
			ch <- res
			return
		    }
		    
		    log.Debug("the dcrm addr confirm validate fail.")
		    var ret2 Err
		    ret2.info = "the dcrm addr confirm validate fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		}

		//ec2
		func dcrm_liloreqAddress(msgprex string,fusionaddr string,pubkey string,cointype string,ch chan interface{}) {

		    GetEnodesInfo()

		    if strings.EqualFold(cointype,"ETH") == false && strings.EqualFold(cointype,"BTC") == false && strings.EqualFold(cointype,"GUSD") == false && strings.EqualFold(cointype,"BNB") == false && strings.EqualFold(cointype,"MKR") == false && strings.EqualFold(cointype,"HT") == false && strings.EqualFold(cointype,"BNT") == false {
			//log.Debug("===========coin type is not supported.must be btc or eth.=================")
			var ret2 Err
			ret2.info = "coin type is not supported."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    log.Debug("===========dcrm_liloreqAddress,","enode_cnts",enode_cnts,"NodeCnt",NodeCnt,"","==============")
		    if int32(enode_cnts) != int32(NodeCnt) {
			log.Debug("============the net group is not ready.please try again.================")
			var ret2 Err
			ret2.info = "the net group is not ready.please try again."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    log.Debug("=========================!!!Start!!!=======================")

		    _,exsit := types.GetDcrmRpcWorkersDataKReady(msgprex)
		    if exsit == false {
			log.Debug("============dcrm_liloreqAddress,get worker id fail.================")
			var ret2 Err
			ret2.info = "get worker id fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    id := getworkerid(msgprex,cur_enode)
		    ok := KeyGenerate_ec2(msgprex,ch,id)
		    if ok == false {
			log.Debug("========dcrm_liloreqAddress,addr generate fail.=========")
			return
		    }

		    spkx,cherr := GetChannelValue(ch_t,workers[id].pkx)
		    if cherr != nil {
			log.Debug("get workers[id].pkx timeout.")
			var ret2 Err
			ret2.info = "get workers[id].pkx timeout."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }
		    pkx := new(big.Int).SetBytes([]byte(spkx))
		    //spky := <- workers[id].pky
		    spky,cherr := GetChannelValue(ch_t,workers[id].pky)
		    if cherr != nil {
			log.Debug("get workers[id].pky timeout.")
			var ret2 Err
			ret2.info = "get workers[id].pky timeout."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }
		    pky := new(big.Int).SetBytes([]byte(spky))
		    ys := secp256k1.S256().Marshal(pkx,pky)

		    //get save
		    save,cherr := GetChannelValue(ch_t,workers[id].save)
		    if cherr != nil {
			log.Debug("get workers[id].save timeout.")
			var ret2 Err
			ret2.info = "get workers[id].save timeout."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    //bitcoin type
		    var bitaddr string
		    if strings.EqualFold(cointype,"BTC") == true {
			_,bitaddr,_ = GenerateBTCTest(ys)
			if bitaddr == "" {
			    var ret2 Err
			    ret2.info = "bitcoin addr gen fail.please try again."
			    res := RpcDcrmRes{ret:"",err:ret2}
			    ch <- res
			    return
			}
		    }
		    //

		    lock.Lock()
		    //write db
		    dir = GetDbDir()
		    db,_ := ethdb.NewLDBDatabase(dir, 0, 0)
		    if db == nil {
			log.Debug("==============create db fail.============")
			var ret2 Err
			ret2.info = "create db fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			lock.Unlock()
			return
		    }

		    var stmp string
		    if strings.EqualFold(cointype,"ETH") == true || strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
			recoveraddress := common.BytesToAddress(crypto.Keccak256(ys[1:])[12:]).Hex()
			stmp = fmt.Sprintf("%s", recoveraddress)
		    }
		    if strings.EqualFold(cointype,"BTC") == true {
			stmp = bitaddr
		    }
		    
		    hash := crypto.Keccak256Hash([]byte(strings.ToLower(fusionaddr) + ":" + strings.ToLower(cointype))).Hex()
		    s := []string{fusionaddr,pubkey,string(ys),save,hash} ////fusionaddr ??
		    ss := strings.Join(s,sep)
		    log.Debug("============dcrm_liloreqAddress,","stmp",stmp,"","=========")
		    db.Put([]byte(stmp),[]byte(ss))

		    //ret := Tool_DecimalByteSlice2HexString(ys[:])
		    //m := AccountListInfo{COINTYPE:cointype,DCRMADDRESS:stmp,DCRMPUBKEY:ret}
		    //b,_ := json.Marshal(m)
		    //

		    res := RpcDcrmRes{ret:stmp,err:nil}
		    ch <- res

		    db.Close()
		    lock.Unlock()
		    if stmp != "" {
			WriteDcrmAddrToLocalDB(fusionaddr,cointype,stmp)
		    }
		}

		func dcrm_reqAddress(msgprex string,pubkey string,cointype string,ch chan interface{}) {
		    return
		}

		func GetTxHashForLockout(realfusionfrom string,realdcrmfrom string,to string,value string,cointype string,signature string) (string,string,error) {
		    //log.Debug("GetTxHashForLockout","real fusion from addr",realfusionfrom,"real from dcrm addr",realdcrmfrom,"value",value,"signature",signature,"cointype",cointype)

		    lockoutx,txerr := getLockoutTx(realfusionfrom,realdcrmfrom,to,value,cointype)
		    
		    if lockoutx == nil || txerr != nil {
			return "","",txerr
		    }

		    if strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
		signedtx, err := MakeSignedTransaction(erc20_client, lockoutx, signature)
		if err != nil {
			//fmt.Printf("%v\n",err)
			return "","",err
		}
		    result,err := signedtx.MarshalJSON()
		    return signedtx.Hash().String(),string(result),err
		    }

		    if strings.EqualFold(cointype,"ETH") {
			// Set chainID
			chainID := big.NewInt(int64(CHAIN_ID))
			signer := types.NewEIP155Signer(chainID)

			// With signature to TX
			message, merr := hex.DecodeString(signature)
			if merr != nil {
				log.Debug("Decode signature error:")
				return "","",merr
			}
			sigTx, signErr := lockoutx.WithSignature(signer, message)
			if signErr != nil {
				log.Debug("signer with signature error:")
				return "","",signErr
			}
			//log.Debug("GetTxHashForLockout","tx hash",sigTx.Hash().String())
			result,err := sigTx.MarshalJSON()
			return sigTx.Hash().String(),string(result),err
		    }

		    return "","",errors.New("get tx hash for lockout error.")
		    
		}

		func SendTxForLockout(realfusionfrom string,realdcrmfrom string,to string,value string,cointype string,signature string) (string,error) {

		    log.Debug("========SendTxForLockout=====")
		    lockoutx,txerr := getLockoutTx(realfusionfrom,realdcrmfrom,to,value,cointype)
		    if lockoutx == nil || txerr != nil {
			return "",txerr
		    }

		    if strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
		signedtx, err := MakeSignedTransaction(erc20_client, lockoutx, signature)
		if err != nil {
			return "",err
		}
		
		res, err := Erc20_sendTx(erc20_client, signedtx)
		if err != nil {
			return "",err
		}
		    return res,nil
		    }

		    if strings.EqualFold(cointype,"ETH") {
			// Set chainID
			chainID := big.NewInt(int64(CHAIN_ID))
			signer := types.NewEIP155Signer(chainID)

			// With signature to TX
			message, merr := hex.DecodeString(signature)
			if merr != nil {
				log.Debug("Decode signature error:")
				return "",merr
			}
			sigTx, signErr := lockoutx.WithSignature(signer, message)
			if signErr != nil {
				log.Debug("signer with signature error:")
				return "",signErr
			}

			// Connect geth RPC port: ./geth --rinkeby --rpc console
			client, err := ethclient.Dial(ETH_SERVER)
			if err != nil {
				log.Debug("client connection error:")
				return "",err
			}
			//log.Debug("HTTP-RPC client connected")

			// Send RawTransaction to ethereum network
			ctx := context.Background()
			txErr := client.SendTransaction(ctx, sigTx)
			if txErr != nil {
				log.Debug("================send tx error:================")
				return sigTx.Hash().String(),txErr
			}
			log.Debug("================send tx success","tx.hash", sigTx.Hash().String(),"","=====================")
			return sigTx.Hash().String(),nil
		    }
		    
		    return "",errors.New("send tx for lockout fail.")
	    }

	    func validate_lockout(msgprex string,txhash_lockout string,lilotx string,fusionfrom string,dcrmfrom string,realfusionfrom string,realdcrmfrom string,lockoutto string,value string,cointype string,ch chan interface{}) {
	    log.Debug("=============validate_lockout============")

	    val,ok := GetLockoutInfoFromLocalDB(txhash_lockout)
	    if ok == nil && val != "" {
		res := RpcDcrmRes{ret:val,err:nil}
		ch <- res
		return
	    }

	    if strings.EqualFold(cointype,"ETH") == true || strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
		lockoutx,txerr := getLockoutTx(realfusionfrom,realdcrmfrom,lockoutto,value,cointype)
		//bug
		if lockoutx == nil || txerr != nil {
		    res := RpcDcrmRes{ret:"",err:txerr}
		    ch <- res
		    return
		}
	    
		chainID := big.NewInt(int64(CHAIN_ID))
		signer := types.NewEIP155Signer(chainID)
		
		rch := make(chan interface{},1)
		//log.Debug("=============validate_lockout","lockout tx hash",signer.Hash(lockoutx).String(),"","=============")
		dcrm_sign(msgprex,"xxx",signer.Hash(lockoutx).String(),realdcrmfrom,cointype,rch)
		//ret := (<- rch).(RpcDcrmRes)
		ret,cherr := GetChannelValue(ch_t,rch)
		if cherr != nil {
		    res := RpcDcrmRes{ret:"",err:cherr}
		    ch <- res
		    return
		}
		//bug
		rets := []rune(ret)
		if len(rets) != 130 {
		    var ret2 Err
		    ret2.info = "wrong size for dcrm sig."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}

		lockout_tx_hash,_,outerr := GetTxHashForLockout(realfusionfrom,realdcrmfrom,lockoutto,value,cointype,ret)
		if outerr != nil {
		    res := RpcDcrmRes{ret:"",err:outerr}
		    ch <- res
		    return
		}

		SendTxForLockout(realfusionfrom,realdcrmfrom,lockoutto,value,cointype,ret)
		retva := lockout_tx_hash + sep10 + realdcrmfrom
		//types.SetDcrmValidateData(txhash_lockout,retva)
		if !strings.EqualFold(txhash_lockout,"xxx") {
		    WriteLockoutInfoToLocalDB(txhash_lockout,retva)
		}
		res := RpcDcrmRes{ret:retva,err:nil}
		ch <- res
		return
	    }

	    if strings.EqualFold(cointype,"BTC") == true {
		amount,_ := strconv.ParseFloat(value, 64)
		rch := make(chan interface{},1)
		lockout_tx_hash := Btc_createTransaction(msgprex,realdcrmfrom,lockoutto,realdcrmfrom,amount,uint32(BTC_BLOCK_CONFIRMS),BTC_DEFAULT_FEE,rch)
		log.Debug("===========btc tx,get return hash",lockout_tx_hash,"","===========")
		if lockout_tx_hash == "" {
		    log.Debug("=============create btc tx fail.=================")
		    var ret2 Err
		    ret2.info = "create btc tx fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}

		log.Debug("=============create btc tx success.=================")
		retva := lockout_tx_hash + sep10 + realdcrmfrom
		//types.SetDcrmValidateData(txhash_lockout,retva)
		if !strings.EqualFold(txhash_lockout,"xxx") {
		    WriteLockoutInfoToLocalDB(txhash_lockout,retva)
		}
		res := RpcDcrmRes{ret:retva,err:nil}
		ch <- res
		return
	    }
	}

		//ec2
		func dcrm_sign(msgprex string,sig string,txhash string,dcrmaddr string,cointype string,ch chan interface{}) {

		    dcrmaddrs := []rune(dcrmaddr)
		    if cointype == "ETH" && len(dcrmaddrs) != 42 { //42 = 2 + 20*2 =====>0x + addr
			var ret2 Err
			ret2.info = "dcrm addr is not right,must be 42,and first with 0x."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    if cointype == "BTC" && ValidateAddress(bitcoin_net,string(dcrmaddrs[:])) == false {
			var ret2 Err
			ret2.info = "dcrm addr is not right."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    if strings.EqualFold(cointype,"ETH") == false && strings.EqualFold(cointype,"BTC") == false {
			log.Debug("===========coin type is not supported.must be btc or eth.=================")
			var ret2 Err
			ret2.info = "coin type is not supported."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }
		     
		    GetEnodesInfo() 
		    
		    if int32(enode_cnts) != int32(NodeCnt) {
			log.Debug("============the net group is not ready.please try again.================")
			var ret2 Err
			ret2.info = "the net group is not ready.please try again."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    log.Debug("===================!!!Start!!!====================")

		    lock.Lock()
		    //db
		    dir = GetDbDir()
		    db,_ := ethdb.NewLDBDatabase(dir, 0, 0)
		    if db == nil {
			log.Debug("===========open db fail.=============")
			var ret2 Err
			ret2.info = "open db fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			lock.Unlock()
			return
		    }
		    //
		    log.Debug("=========dcrm_sign,","dcrmaddr",dcrmaddr,"","==============")
		    has,_ := db.Has([]byte(dcrmaddr))
		    if has == false {
			log.Debug("===========user is not register.=============")
			var ret2 Err
			ret2.info = "user is not register."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			db.Close()
			lock.Unlock()
			return
		    }

		    data,_ := db.Get([]byte(dcrmaddr))
		    datas := strings.Split(string(data),sep)

		    save := datas[3] 
		    
		    dcrmpub := datas[2]
		    dcrmpks := []byte(dcrmpub)
		    dcrmpkx,dcrmpky := secp256k1.S256().Unmarshal(dcrmpks[:])

		    txhashs := []rune(txhash)
		    if string(txhashs[0:2]) == "0x" {
			txhash = string(txhashs[2:])
		    }

		    db.Close()
		    lock.Unlock()

		    id := getworkerid(msgprex,cur_enode)
		    log.Debug("===================before sign_ec2====================")

		    Sign_ec2(msgprex,save,txhash,cointype,dcrmpkx,dcrmpky,ch,id)
		}
		
		func DisMsg(msg string) {

		    if msg == "" {
			return
		    }

		    //ec2
		    IsEc2 := true
		    if IsEc2 == true {
			//msg:  prex-enode:C1:X1:X2
			mm := strings.Split(msg, sep)
			if len(mm) < 3 {
			    return
			}

			mms := mm[0]
			id := getworkerid(mms,cur_enode)
			w := workers[id]

			msgCode := mm[1]
			switch msgCode {
			case "C1":
			    w.msg_c1 <-msg
			    if len(w.msg_c1) == (TOTALNODES-1) {
				w.bc1 <- true
			    }
			case "D1":
			    w.msg_d1_1 <-msg
			    if len(w.msg_d1_1) == (TOTALNODES-1) {
				w.bd1_1 <- true
			    }
			case "SHARE1":
			    w.msg_share1 <-msg
			    if len(w.msg_share1) == (TOTALNODES-1) {
				w.bshare1 <- true
			    }
			    //sign
		       case "C11":
			    w.msg_c11 <-msg
			    if len(w.msg_c11) == (TOTALNODES-1) {
				w.bc11 <- true
			    }
		       case "KC":
			    w.msg_kc <-msg
			    if len(w.msg_kc) == (TOTALNODES-1) {
				w.bkc <- true
			    }
		       case "MKG":
			    w.msg_mkg <-msg
			    if len(w.msg_mkg) == (TOTALNODES-1) {
				w.bmkg <- true
			    }
		       case "MKW":
			    w.msg_mkw <-msg
			    if len(w.msg_mkw) == (TOTALNODES-1) {
				w.bmkw <- true
			    }
		       case "DELTA1":
			    w.msg_delta1 <-msg
			    if len(w.msg_delta1) == (TOTALNODES-1) {
				w.bdelta1 <- true
			    }
			case "D11":
			    w.msg_d11_1 <-msg
			    if len(w.msg_d11_1) == (TOTALNODES-1) {
				w.bd11_1 <- true
			    }
			case "S1":
			    w.msg_s1 <-msg
			    if len(w.msg_s1) == (TOTALNODES-1) {
				w.bs1 <- true
			    }
			case "SS1":
			    w.msg_ss1 <-msg
			    if len(w.msg_ss1) == (TOTALNODES-1) {
				w.bss1 <- true
			    }
			default:
			    log.Debug("unkown msg code")
			}

			return
		    }
		}

		func SetUpMsgList(msg string) {

		    log.Debug("==========SetUpMsgList,","receiv msg",msg,"","===================")
		    mm := strings.Split(msg,"dcrmslash")
		    if len(mm) >= 2 {
			receiveSplitKey(msg)
			return
		    }

		    mm = strings.Split(msg,msgtypesep)
		    if len(mm) == 2 {
			if mm[1] == "rpc_req_dcrmaddr" {
			    mmm := strings.Split(mm[0],sep)
			    prex := mmm[0]
			    _,ok := types.GetDcrmRpcMsgDataKReady(prex)
			    if ok {
				return
			    }
			    
			    types.SetDcrmRpcMsgData(prex,msg)
			    log.Debug("SetUpMsgList","broatcast rpc msg",msg)
			    p2pdcrm.Broatcast(msg)
			    if !IsInGroup() {
				go func(s string) {
				     time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
				     types.DeleteDcrmRpcMsgData(s)
				     types.DeleteDcrmRpcWorkersData(s)
				     types.DeleteDcrmRpcResData(s)
				}(prex)
				return
			    }
			}
			if mm[1] == "rpc_req_dcrmaddr_res" {
			    mmm := strings.Split(mm[0],sep)
			    prex := mmm[0]
			    _,ok := types.GetDcrmRpcResDataKReady(prex)
			    if ok {
				return
			    }
			    types.SetDcrmRpcResData(prex,msg)
			    log.Debug("SetUpMsgList","broatcast rpc res msg",msg)
			    p2pdcrm.Broatcast(msg)
			    prexs := strings.Split(prex,"-")
			    if prexs[0] == cur_enode {
				wid,ok := types.GetDcrmRpcWorkersDataKReady(prex)
				if ok {
				    if IsInGroup() {
					//id,_ := strconv.Atoi(wid)
					//w := workers[id]
					//w.dcrmret <-mmm[1]
				    } else {
					id,_ := strconv.Atoi(wid)
					w := non_dcrm_workers[id]
					w.dcrmret <-mmm[1]
				    }
				}
			    }

			    go func(s string) {
				 time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
				 types.DeleteDcrmRpcMsgData(s)
				 types.DeleteDcrmRpcWorkersData(s)
				 types.DeleteDcrmRpcResData(s)
			    }(prex)
			    
			    return
			}

			//confirm
			if mm[1] == "rpc_confirm_dcrmaddr" {
			    mmm := strings.Split(mm[0],sep)
			    prex := mmm[0]
			    _,ok := types.GetDcrmRpcMsgDataKReady(prex)
			    if ok {
				return
			    }
			    
			    types.SetDcrmRpcMsgData(prex,msg)
			    log.Debug("SetUpMsgList","broatcast rpc msg",msg)
			    p2pdcrm.Broatcast(msg)
			    if !IsInGroup() {
				go func(s string) {
				     time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
				     types.DeleteDcrmRpcMsgData(s)
				     types.DeleteDcrmRpcWorkersData(s)
				     types.DeleteDcrmRpcResData(s)
				}(prex)
				return
			    }
			}
			if mm[1] == "rpc_confirm_dcrmaddr_res" {
			    mmm := strings.Split(mm[0],sep)
			    prex := mmm[0]
			    _,ok := types.GetDcrmRpcResDataKReady(prex)
			    if ok {
				return
			    }
			    types.SetDcrmRpcResData(prex,msg)
			    log.Debug("SetUpMsgList","broatcast rpc res msg",msg)
			    p2pdcrm.Broatcast(msg)
			    prexs := strings.Split(prex,"-")
			    if prexs[0] == cur_enode {
				wid,ok := types.GetDcrmRpcWorkersDataKReady(prex)
				if ok {
				    if IsInGroup() {
					//id,_ := strconv.Atoi(wid)
					//w := workers[id]
					//w.dcrmret <-mmm[1]
				    } else {
					id,_ := strconv.Atoi(wid)
					w := non_dcrm_workers[id]
					w.dcrmret <-mmm[1]
				    }
				}
			    }

			    go func(s string) {
				 time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
				 types.DeleteDcrmRpcMsgData(s)
				 types.DeleteDcrmRpcWorkersData(s)
				 types.DeleteDcrmRpcResData(s)
			    }(prex)
			    
			    return
			}

			//lockin
			if mm[1] == "rpc_lockin" {
			    mmm := strings.Split(mm[0],sep)
			    prex := mmm[0]
			    _,ok := types.GetDcrmRpcMsgDataKReady(prex)
			    if ok {
				return
			    }
			    
			    types.SetDcrmRpcMsgData(prex,msg)
			    log.Debug("SetUpMsgList","broatcast rpc msg",msg)
			    p2pdcrm.Broatcast(msg)
			    if !IsInGroup() {
				go func(s string) {
				     time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
				     types.DeleteDcrmRpcMsgData(s)
				     types.DeleteDcrmRpcWorkersData(s)
				     types.DeleteDcrmRpcResData(s)
				}(prex)
				return
			    }
			}
			if mm[1] == "rpc_lockin_res" {
			    mmm := strings.Split(mm[0],sep)
			    prex := mmm[0]
			    _,ok := types.GetDcrmRpcResDataKReady(prex)
			    if ok {
				return
			    }
			    types.SetDcrmRpcResData(prex,msg)
			    log.Debug("SetUpMsgList","broatcast rpc res msg",msg)
			    p2pdcrm.Broatcast(msg)
			    prexs := strings.Split(prex,"-")
			    if prexs[0] == cur_enode {
				wid,ok := types.GetDcrmRpcWorkersDataKReady(prex)
				if ok {
				    if IsInGroup() {
					//id,_ := strconv.Atoi(wid)
					//w := workers[id]
					//w.dcrmret <-mmm[1]
				    } else {
					id,_ := strconv.Atoi(wid)
					w := non_dcrm_workers[id]
					w.dcrmret <-mmm[1]
				    }
				}
			    }

			    go func(s string) {
				 time.Sleep(time.Duration(200)*time.Second) //1000 == 1s
				 types.DeleteDcrmRpcMsgData(s)
				 types.DeleteDcrmRpcWorkersData(s)
				 types.DeleteDcrmRpcResData(s)
			    }(prex)
			    
			    return
			}

			//lockout
			if mm[1] == "rpc_lockout" {
			    mmm := strings.Split(mm[0],sep)
			    prex := mmm[0]
			    val,ok := types.GetDcrmRpcMsgDataKReady(prex)
			    log.Debug("SetUpMsgList","prex",prex)
			    log.Debug("SetUpMsgList","val",val)
			    if ok {
				return
			    }
			    
			    types.SetDcrmRpcMsgData(prex,msg)
			    log.Debug("SetUpMsgList","broatcast rpc msg",msg)
			    p2pdcrm.Broatcast(msg)
			    if !IsInGroup() {
				log.Debug("========SetUpMsgList,it is not in group.===================")
				go func(s string) {
				     time.Sleep(time.Duration(500)*time.Second) //1000 == 1s
				     types.DeleteDcrmRpcMsgData(s)
				     types.DeleteDcrmRpcWorkersData(s)
				     types.DeleteDcrmRpcResData(s)
				}(prex)
				return
			    }
			}
			if mm[1] == "rpc_lockout_res" {
			    mmm := strings.Split(mm[0],sep)
			    prex := mmm[0]
			    _,ok := types.GetDcrmRpcResDataKReady(prex)
			    if ok {
				return
			    }
			    types.SetDcrmRpcResData(prex,msg)
			    log.Debug("SetUpMsgList","broatcast rpc res msg",msg)
			    p2pdcrm.Broatcast(msg)
			    prexs := strings.Split(prex,"-")
			    if prexs[0] == cur_enode {
				wid,ok := types.GetDcrmRpcWorkersDataKReady(prex)
				if ok {
				    if IsInGroup() {
					//id,_ := strconv.Atoi(wid)
					//w := workers[id]
					//w.dcrmret <-mmm[1]
				    } else {
					id,_ := strconv.Atoi(wid)
					w := non_dcrm_workers[id]
					w.dcrmret <-mmm[1]
				    }
				}
			    }

			    go func(s string) {
				 time.Sleep(time.Duration(500)*time.Second) //1000 == 1s
				 types.DeleteDcrmRpcMsgData(s)
				 types.DeleteDcrmRpcWorkersData(s)
				 types.DeleteDcrmRpcResData(s)
			    }(prex)
			    
			    return
			}
		    }

		    v := RecvMsg{msg:msg}
		    //rpc-req
		    rch := make(chan interface{},1)
		    //req := RpcReq{rpcstr:msg,ch:rch}
		    req := RpcReq{rpcdata:&v,ch:rch}
		    RpcReqQueue <- req
		}

		func findds(s string,ds []string) string { //msgprex-enode:C1:X1:X2
		    ss := strings.Split(s, sep)
		    sss := ss[0]
		    ens := strings.Split(sss, "-")
		    en := ens[len(ens)-1]
		    for _,v := range ds {
			vs := strings.Split(v, sep)
			vss := vs[0]
			des := strings.Split(vss, "-")
			if des[len(des)-1] == en {
			    return v
			}
		    }

		    return ""
		}

//==========================================================

type AccountListJson struct {
    ACCOUNTLIST []AccountListInfo
}

type AccountListInfo struct {
    COINTYPE string
    DCRMADDRESS string
    DCRMPUBKEY string
}

type NodeJson struct {
    ARRAY []NodeInfo
}
type NodeInfo struct {
    IP string
    NAME string
    RPCPORT string
}
//============================================================

//API
func Dcrm_GetAccountList(pubkey string) (string,error) {
    pub := []rune(pubkey)
    if len(pub) != 132 { //132 = 4 + 64 + 64
	log.Debug("===========pubkey len is not 132. (0x04xxxxxx)=================")
	var ret3 Err
	ret3.info = "pubkey len is not 132. must be (0x04xxxxxxx)" 
	return "",ret3
    }

    lock.Lock()
    //db
    dir = GetDbDir()
    db,_ := ethdb.NewLDBDatabase(dir, 0, 0)
    if db == nil {
	var ret3 Err
	ret3.info = "create db fail." 
	lock.Unlock()
	return "",ret3
    }
    //
    has,_ := db.Has([]byte(pubkey))
    if has == false {
	var ret3 Err
	ret3.info = "user is not register." 
	db.Close()
	lock.Unlock()
	return "",ret3
    }

    data,_ := db.Get([]byte(pubkey))
    datas := strings.Split(string(data),sep)
    var jsonData AccountListJson
    for _,lists := range datas {
	var m AccountListInfo
	ok := json.Unmarshal([]byte(lists), &m)
	if ok == nil {
	    jsonData.ACCOUNTLIST = append(jsonData.ACCOUNTLIST,m)
	}
    }
    
    b, err := json.Marshal(jsonData)
    if err  != nil {
	db.Close()
	lock.Unlock()
	return "",err
    }
    db.Close()
    lock.Unlock()
    return string(b),nil
}

func Dcrm_NodeInfo() (string, error) {
    _,nodes := p2pdcrm.GetEnodes()
    others := strings.Split(nodes,sep2)
    var jsonData NodeJson
    for _,ens := range others {
	en := strings.Split(ens,"@")
	jsonData.ARRAY = append(jsonData.ARRAY,NodeInfo{IP:en[1],NAME:"",RPCPORT:"40405"})
    }

    b, err := json.Marshal(jsonData)
    if err  != nil {
	return "",err
    }

    return string(b),nil
}

//func Dcrm_ReqAddress(pubkey string,cointype string) (string, error) {
func Dcrm_ReqAddress(wr WorkReq) (string, error) {
    //rpc-req
    /*ss := "Dcrm_ReqAddress" + sep3 + pubkey + sep3 + cointype
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:ss,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)*/
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    //ret := (<- rch).(RpcDcrmRes)
    ret,cherr := GetChannelValue(ch_t,rch)
    if cherr != nil {
	log.Debug("Dcrm_ReqAddress timeout.")
	return "",errors.New("Dcrm_ReqAddress timeout.")
    }
    log.Debug("=========================keygen finish.=======================")
    return ret,cherr
}

func Dcrm_ConfirmAddr(wr WorkReq) (string, error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    //ret := (<- rch).(RpcDcrmRes)
    ret,cherr := GetChannelValue(ch_t,rch)
    if cherr != nil {
	log.Debug(cherr.Error())
	return "",cherr
    }
    return ret,cherr
}

func Dcrm_LiLoReqAddress(wr WorkReq) (string, error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    //ret := (<- rch).(RpcDcrmRes)
    ret,cherr := GetChannelValue(ch_t,rch)
    if cherr != nil {
	log.Debug("Dcrm_LiLoReqAddress timeout.")
	return "",errors.New("Dcrm_LiLoReqAddress timeout.")
    }
    //log.Debug("Dcrm_LiLoReqAddress","ret",ret)
    return ret,cherr
}

func Dcrm_Sign(wr WorkReq) (string,error) {
    //rpc-req
    /*rch := make(chan interface{},1)
    ss := "Dcrm_Sign" + sep3 + sig + sep3 + txhash + sep3 + dcrmaddr + sep3 + cointype
    req := RpcReq{rpcdata:ss,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)*/
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    //ret := (<- rch).(RpcDcrmRes)
    ret,cherr := GetChannelValue(ch_t,rch)
    if cherr != nil {
	log.Debug("Dcrm_Sign get timeout.")
	log.Debug(cherr.Error())
	return "",cherr
    }
    return ret,cherr
    //rpc-req
}

func Dcrm_LockIn(tx string,txhashs []string) (string, error) {
    return "",nil
}

func Validate_Lockout(wr WorkReq) (string, error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    //ret := (<- rch).(RpcDcrmRes)
    ret,cherr := GetChannelValue(ch_t,rch) //80
    if cherr != nil {
	log.Debug("==========Validate_Lockout,","get error",cherr.Error(),"","===========")
	return "",cherr
    }
    log.Debug("==========Validate_Lockout,success.","return data",ret,"","===========")
    return ret,cherr
}

//==============================================================

func IsCurNode(enodes string,cur string) bool {
    if enodes == "" || cur == "" {
	return false
    }

    s := []rune(enodes)
    en := strings.Split(string(s[8:]),"@")
    //log.Debug("=======IsCurNode,","en[0]",en[0],"cur",cur,"","============")
    if en[0] == cur {
	return true
    }

    return false
}

func DoubleHash(id string) *big.Int {
    // Generate the random num
    //rnd := random.GetRandomInt(256)

    // First, hash with the keccak256
    keccak256 := sha3.NewKeccak256()
    //keccak256.Write(rnd.Bytes())

    keccak256.Write([]byte(id))

    digestKeccak256 := keccak256.Sum(nil)

    //second, hash with the SHA3-256
    sha3256 := sha3.New256()

    sha3256.Write(digestKeccak256)

    digest := sha3256.Sum(nil)

    // convert the hash ([]byte) to big.Int
    digestBigInt := new(big.Int).SetBytes(digest)
    return digestBigInt
}

func Tool_DecimalByteSlice2HexString(DecimalSlice []byte) string {
    var sa = make([]string, 0)
    for _, v := range DecimalSlice {
        sa = append(sa, fmt.Sprintf("%02X", v))
    }
    ss := strings.Join(sa, "")
    return ss
}

func GetSignString(r *big.Int,s *big.Int,v int32,i int) string {
    rr :=  r.Bytes()
    sss :=  s.Bytes()

    //bug
    if len(rr) == 31 && len(sss) == 32 {
	log.Debug("======r len is 31===========")
	sigs := make([]byte,65)
	sigs[0] = byte(0)
	math.ReadBits(r,sigs[1:32])
	math.ReadBits(s,sigs[32:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    if len(rr) == 31 && len(sss) == 31 {
	log.Debug("======r and s len is 31===========")
	sigs := make([]byte,65)
	sigs[0] = byte(0)
	sigs[32] = byte(0)
	math.ReadBits(r,sigs[1:32])
	math.ReadBits(s,sigs[33:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    if len(rr) == 32 && len(sss) == 31 {
	log.Debug("======s len is 31===========")
	sigs := make([]byte,65)
	sigs[32] = byte(0)
	math.ReadBits(r,sigs[0:32])
	math.ReadBits(s,sigs[33:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    //

    n := len(rr) + len(sss) + 1
    sigs := make([]byte,n)
    math.ReadBits(r,sigs[0:len(rr)])
    math.ReadBits(s,sigs[len(rr):len(rr)+len(sss)])

    sigs[len(rr)+len(sss)] = byte(i)
    ret := Tool_DecimalByteSlice2HexString(sigs)

    return ret
}

func Verify(r *big.Int,s *big.Int,v int32,message string,pkx *big.Int,pky *big.Int) bool {
    return Verify2(r,s,v,message,pkx,pky)
}

func GetEnodesByUid(uid *big.Int) string {
    _,nodes := p2pdcrm.GetEnodes()
    others := strings.Split(nodes,sep2)
    for _,v := range others {
	id := DoubleHash(v)
	if id.Cmp(uid) == 0 {
	    return v
	}
    }

    return ""
}

type sortableIDSSlice []*big.Int

func (s sortableIDSSlice) Len() int {
	return len(s)
}

func (s sortableIDSSlice) Less(i, j int) bool {
	return s[i].Cmp(s[j]) <= 0
}

func (s sortableIDSSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func GetIds() sortableIDSSlice {
    var ids sortableIDSSlice
    _,nodes := p2pdcrm.GetEnodes()
    others := strings.Split(nodes,sep2)
    for _,v := range others {
	uid := DoubleHash(v)
	ids = append(ids,uid)
    }
    sort.Sort(ids)
    return ids
}

//ec2
func KeyGenerate_ec2(msgprex string,ch chan interface{},id int) bool {
    w := workers[id]
    ns,_ := p2pdcrm.GetEnodes()
    if ns != TOTALNODES {
	var ret2 Err
	ret2.info = "get nodes info error in keygenerate."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }

    u1 := random.GetRandomIntFromZn(secp256k1.S256().N)
    u1Gx, u1Gy := secp256k1.S256().ScalarBaseMult(u1.Bytes())
    commitU1G := new(commit.Commitment).Commit(u1Gx, u1Gy)
    u1PaillierPk, u1PaillierSk := paillier.GenerateKeyPair(PaillierKeyLength)

    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "C1"
    s1 := string(commitU1G.C.Bytes())
    s2 := u1PaillierPk.Length
    s3 := string(u1PaillierPk.N.Bytes()) 
    s4 := string(u1PaillierPk.G.Bytes()) 
    s5 := string(u1PaillierPk.N2.Bytes()) 
    ss := enode + sep + s0 + sep + s1 + sep + s2 + sep + s3 + sep + s4 + sep + s5
    log.Debug("================kg ec2 round one,send msg,code is C1==================")
    SendMsgToDcrmGroup(ss)

     _,cherr := GetChannelValue(ch_t,w.bc1)
    if cherr != nil {
	log.Debug("get w.bc1 timeout.")
	var ret2 Err
	ret2.info = "get C1 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }

    ids := GetIds()

    u1PolyG, _, u1Shares, err := vss.Vss(u1, ids, THRESHOLD, TOTALNODES)
    if err != nil {
	res := RpcDcrmRes{ret:"",err:err}
	ch <- res
	return false 
    }

    for _,id := range ids {
	enodes := GetEnodesByUid(id)

	if enodes == "" {
	    log.Debug("=========KeyGenerate_ec2,don't find proper enodes========")
	    var ret2 Err
	    ret2.info = "don't find proper enodes."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return false
	}
	
	if IsCurNode(enodes,cur_enode) {
	    continue
	}

	for _,v := range u1Shares {
	    uid := vss.GetSharesId(v)
	    if uid.Cmp(id) == 0 {
		mp := []string{msgprex,cur_enode}
		enode := strings.Join(mp,"-")
		s0 := "SHARE1"
		s1 := strconv.Itoa(v.T) 
		s2 := string(v.Id.Bytes()) 
		s3 := string(v.Share.Bytes()) 
		ss := enode + sep + s0 + sep + s1 + sep + s2 + sep + s3
		log.Debug("================kg ec2 round two,send msg,code is SHARE1==================")
		p2pdcrm.SendMsgToPeer(enodes,ss)
		break
	    }
	}
    }

    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "D1"
    dlen := len(commitU1G.D)
    s1 = strconv.Itoa(dlen)

    ss = enode + sep + s0 + sep + s1 + sep
    for _,d := range commitU1G.D {
	ss += string(d.Bytes())
	ss += sep
    }

    s2 = strconv.Itoa(u1PolyG.T)
    s3 = strconv.Itoa(u1PolyG.N)
    ss = ss + s2 + sep + s3 + sep

    pglen := 2*(len(u1PolyG.PolyG))
    log.Debug("=========KeyGenerate_ec2,","pglen",pglen,"","==========")
    s4 = strconv.Itoa(pglen)

    ss = ss + s4 + sep

    for _,p := range u1PolyG.PolyG {
	for _,d := range p {
	    ss += string(d.Bytes())
	    ss += sep
	}
    }
    ss = ss + "NULL"
    log.Debug("================kg ec2 round three,send msg,code is D1==================")
    SendMsgToDcrmGroup(ss)

    _,cherr = GetChannelValue(ch_t,w.bd1_1)
    if cherr != nil {
	log.Debug("get w.bd1_1 timeout in keygenerate.")
	var ret2 Err
	ret2.info = "get D1 timeout in keygenerate."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }

    _,cherr = GetChannelValue(ch_t,w.bshare1)
    if cherr != nil {
	log.Debug("get w.bshare1 timeout in keygenerate.")
	var ret2 Err
	ret2.info = "get SHARE1 timeout in keygenerate."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }
	 
    var i int
    shares := make([]string,TOTALNODES-1)
    for i=0;i<(TOTALNODES-1);i++ {
	//v := <-w.msg_d1_1
	v,cherr := GetChannelValue(ch_t,w.msg_share1)
	if cherr != nil {
	    log.Debug("get w.msg_share1 timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_share1 timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return false
	}
	shares[i] = v
    }
    
    var sstruct = make(map[string]*vss.ShareStruct)
    for _,v := range shares {
	mm := strings.Split(v, sep)
	t,_ := strconv.Atoi(mm[2])
	ushare := &vss.ShareStruct{T:t,Id:new(big.Int).SetBytes([]byte(mm[3])),Share:new(big.Int).SetBytes([]byte(mm[4]))}
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	sstruct[prexs[len(prexs)-1]] = ushare
    }
    for _,v := range u1Shares {
	uid := vss.GetSharesId(v)
	enodes := GetEnodesByUid(uid)
	//en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    sstruct[cur_enode] = v 
	    break
	}
    }

    ds := make([]string,TOTALNODES-1)
    for i=0;i<(TOTALNODES-1);i++ {
	//v := <-w.msg_d1_1
	v,cherr := GetChannelValue(ch_t,w.msg_d1_1)
	if cherr != nil {
	    log.Debug("get w.msg_d1_1 timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_d1_1 timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return false
	}
	ds[i] = v
    }
    var upg = make(map[string]*vss.PolyGStruct)
    for _,v := range ds {
	mm := strings.Split(v, sep)
	dlen,_ := strconv.Atoi(mm[2])
	pglen,_ := strconv.Atoi(mm[3+dlen+2])
	pglen = (pglen/2)
	var pgss = make([][]*big.Int, 0)
	l := 0
	for j:=0;j<pglen;j++ {
	    l++
	    var gg = make([]*big.Int,0)
	    gg = append(gg,new(big.Int).SetBytes([]byte(mm[5+dlen+l])))
	    l++
	    gg = append(gg,new(big.Int).SetBytes([]byte(mm[5+dlen+l])))
	    pgss = append(pgss,gg)
	    log.Debug("=========KeyGenerate_ec2,","gg",gg,"pgss",pgss,"","========")
	}

	t,_ := strconv.Atoi(mm[3+dlen])
	n,_ := strconv.Atoi(mm[4+dlen])
	ps := &vss.PolyGStruct{T:t,N:n,PolyG:pgss}
	//pstruct = append(pstruct,ps)
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	upg[prexs[len(prexs)-1]] = ps
    }
    upg[cur_enode] = u1PolyG

    log.Debug("[Key Generation ec2][Round 3] 3. u1 verify share:")
    
    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if sstruct[en[0]].Verify(upg[en[0]]) == false {
	    log.Debug("u1 verify share fail.")
	    var ret2 Err
	    ret2.info = "u1 verify share fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return false
	}
    }

    cs := make([]string,TOTALNODES-1)
    for i=0;i<(TOTALNODES-1);i++ {
	v,cherr := GetChannelValue(ch_t,w.msg_c1)
	if cherr != nil {
	    log.Debug("get w.msg_c1 timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_c1 timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return false
	}
	cs[i] = v
    }

    var udecom = make(map[string]*commit.Commitment)
    for _,v := range cs {
	mm := strings.Split(v, sep)
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	for _,vv := range ds {
	    mmm := strings.Split(vv, sep)
	    prex2 := mmm[0]
	    prexs2 := strings.Split(prex2,"-")
	    if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
		dlen,_ := strconv.Atoi(mmm[2])
		var gg = make([]*big.Int,0)
		l := 0
		for j:=0;j<dlen;j++ {
		    l++
		    gg = append(gg,new(big.Int).SetBytes([]byte(mmm[2+l])))
		}
		deCommit := &commit.Commitment{C:new(big.Int).SetBytes([]byte(mm[2])), D:gg}
		log.Debug("=========KeyGenerate_ec2,","deCommit",deCommit,"","==========")
		udecom[prexs[len(prexs)-1]] = deCommit
		break
	    }
	}
    }
    deCommit_commitU1G := &commit.Commitment{C: commitU1G.C, D: commitU1G.D}
    udecom[cur_enode] = deCommit_commitU1G

    log.Debug("[Key Generation ec2][Round 3] 4. all users verify commit:")
    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	log.Debug("===========KeyGenerate_ec2,","node",en[0],"deCommit",udecom[en[0]],"","==============")
	if udecom[en[0]].Verify() == false {
	    log.Debug("u1 verify commit in keygenerate fail.")
	    var ret2 Err
	    ret2.info = "u1 verify commit in keygenerate fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return false
	}
    }

    var ug = make(map[string][]*big.Int)
    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	_, u1G := udecom[en[0]].DeCommit()
	ug[en[0]] = u1G
    }

    var pkx *big.Int
    var pky *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	pkx = (ug[en[0]])[0]
	pky = (ug[en[0]])[1]
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	pkx, pky = secp256k1.S256().Add(pkx, pky, (ug[en[0]])[0],(ug[en[0]])[1])
    }
    log.Debug("=========KeyGenerate_ec2,","pkx",pkx,"pky",pky,"","============")
    w.pkx <- string(pkx.Bytes())
    w.pky <- string(pky.Bytes())

    var skU1 *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	skU1 = sstruct[en[0]].Share
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	skU1 = new(big.Int).Add(skU1,sstruct[en[0]].Share)
    }
    skU1 = new(big.Int).Mod(skU1, secp256k1.S256().N)
    log.Debug("=========KeyGenerate_ec2,","skU1",skU1,"","============")

    ss = string(skU1.Bytes())
    ss = ss + sep11
    s1 = u1PaillierSk.Length
    s2 = string(u1PaillierSk.L.Bytes()) 
    s3 = string(u1PaillierSk.U.Bytes())
    ss = ss + s1 + sep11 + s2 + sep11 + s3 + sep11

    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    s1 = u1PaillierPk.Length
	    s2 = string(u1PaillierPk.N.Bytes()) 
	    s3 = string(u1PaillierPk.G.Bytes()) 
	    s4 = string(u1PaillierPk.N2.Bytes()) 
	    ss = ss + s1 + sep11 + s2 + sep11 + s3 + sep11 + s4 + sep11
	    continue
	}
	for _,v := range cs {
	    mm := strings.Split(v, sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		s1 = mm[3] 
		s2 = mm[4] 
		s3 = mm[5] 
		s4 = mm[6] 
		ss = ss + s1 + sep11 + s2 + sep11 + s3 + sep11 + s4 + sep11
		break
	    }
	}
    }
    ss = ss + "NULL"

    w.save <- ss
    return true
}

func Sign_ec2(msgprex string,save string,message string,tokenType string,pkx *big.Int,pky *big.Int,ch chan interface{},id int) {
    log.Debug("===================Sign_ec2====================")
    w := workers[id]
    
    ids := GetIds()
    idSign := ids[:THRESHOLD]
	
    var self *big.Int
    lambda1 := big.NewInt(1)
    for _,uid := range idSign {
	enodes := GetEnodesByUid(uid)
	if IsCurNode(enodes,cur_enode) {
	    self = uid
	    break
	}
    }
    for i,uid := range idSign {
	enodes := GetEnodesByUid(uid)
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	
	sub := new(big.Int).Sub(idSign[i], self)
	subInverse := new(big.Int).ModInverse(sub,secp256k1.S256().N)
	times := new(big.Int).Mul(subInverse, idSign[i])
	lambda1 = new(big.Int).Mul(lambda1, times)
	lambda1 = new(big.Int).Mod(lambda1, secp256k1.S256().N)
    }
    mm := strings.Split(save, sep11)
    skU1 := new(big.Int).SetBytes([]byte(mm[0]))
    w1 := new(big.Int).Mul(lambda1, skU1)
    w1 = new(big.Int).Mod(w1,secp256k1.S256().N)
    
    u1K := random.GetRandomIntFromZn(secp256k1.S256().N)
    u1Gamma := random.GetRandomIntFromZn(secp256k1.S256().N)
    
    u1GammaGx,u1GammaGy := secp256k1.S256().ScalarBaseMult(u1Gamma.Bytes())
    commitU1GammaG := new(commit.Commitment).Commit(u1GammaGx, u1GammaGy)

    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "C11"
    s1 := string(commitU1GammaG.C.Bytes())
    ss := enode + sep + s0 + sep + s1
    log.Debug("================sign ec2 round one,send msg,code is C11==================")
    SendMsgToDcrmGroup(ss)

     _,cherr := GetChannelValue(ch_t,w.bc11)
    if cherr != nil {
	log.Debug("get w.bc11 timeout.")
	var ret2 Err
	ret2.info = "get C11 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }
    
    var ukc = make(map[string]*big.Int)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1KCipher, _ := u1PaillierPk.Encrypt(u1K)
	    ukc[en[0]] = u1KCipher
	    break
	}
    }

    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "KC"
    s1 = string(ukc[cur_enode].Bytes())
    ss = enode + sep + s0 + sep + s1
    log.Debug("================sign ec2 round two,send msg,code is KC==================")
    SendMsgToDcrmGroup(ss)

     _,cherr = GetChannelValue(ch_t,w.bkc)
    if cherr != nil {
	log.Debug("get w.bkc timeout.")
	var ret2 Err
	ret2.info = "get KC timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    var i int
    kcs := make([]string,THRESHOLD-1)
    for i=0;i<(THRESHOLD-1);i++ {
	v,cherr := GetChannelValue(ch_t,w.msg_kc)
	if cherr != nil {
	    log.Debug("get w.msg_kc timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_kc timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
	kcs[i] = v
    }
    for _,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range kcs {
	    mm := strings.Split(v, sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		kc := new(big.Int).SetBytes([]byte(mm[2]))
		ukc[en[0]] = kc
		break
	    }
	}
    }
    
    NSalt := new(big.Int).Lsh(big.NewInt(1), uint(PaillierKeyLength-PaillierKeyLength/10))
    NSubN2 := new(big.Int).Mul(secp256k1.S256().N, secp256k1.S256().N)
    NSubN2 = new(big.Int).Sub(NSalt, NSubN2)
    MinusOne := big.NewInt(-1)
    
    betaU1Star := make([]*big.Int,THRESHOLD)
    betaU1 := make([]*big.Int,THRESHOLD)
    for i=0;i<THRESHOLD;i++ {
	beta1U1Star := random.GetRandomIntFromZn(NSubN2)
	beta1U1 := new(big.Int).Mul(MinusOne, beta1U1Star)
	betaU1Star[i] = beta1U1Star
	betaU1[i] = beta1U1
    }

    vU1Star := make([]*big.Int,THRESHOLD)
    vU1 := make([]*big.Int,THRESHOLD)
    for i=0;i<THRESHOLD;i++ {
	v1U1Star := random.GetRandomIntFromZn(NSubN2)
	v1U1 := new(big.Int).Mul(MinusOne, v1U1Star)
	vU1Star[i] = v1U1Star
	vU1[i] = v1U1
    }

    var mkg = make(map[string]*big.Int)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1KGamma1Cipher := u1PaillierPk.HomoMul(ukc[en[0]], u1Gamma)
	    beta1U1StarCipher, _ := u1PaillierPk.Encrypt(betaU1Star[k])
	    u1KGamma1Cipher = u1PaillierPk.HomoAdd(u1KGamma1Cipher, beta1U1StarCipher) // send to u1
	    mkg[en[0]] = u1KGamma1Cipher
	    continue
	}
	
	u2PaillierPk := GetPaillierPk(save,k)
	u2KGamma1Cipher := u2PaillierPk.HomoMul(ukc[en[0]], u1Gamma)
	beta2U1StarCipher, _ := u2PaillierPk.Encrypt(betaU1Star[k])
	u2KGamma1Cipher = u2PaillierPk.HomoAdd(u2KGamma1Cipher, beta2U1StarCipher) // send to u2
	mp = []string{msgprex,cur_enode}
	enode = strings.Join(mp,"-")
	s0 = "MKG"
	s1 = string(u2KGamma1Cipher.Bytes()) 
	ss = enode + sep + s0 + sep + s1
	log.Debug("================kg ec2 round three,send msg,code is MKG==================")
	p2pdcrm.SendMsgToPeer(enodes,ss)
    }
    
    var mkw = make(map[string]*big.Int)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1Kw1Cipher := u1PaillierPk.HomoMul(ukc[en[0]], w1)
	    v1U1StarCipher, _ := u1PaillierPk.Encrypt(vU1Star[k])
	    u1Kw1Cipher = u1PaillierPk.HomoAdd(u1Kw1Cipher, v1U1StarCipher) // send to u1
	    mkw[en[0]] = u1Kw1Cipher
	    continue
	}
	
	u2PaillierPk := GetPaillierPk(save,k)
	u2Kw1Cipher := u2PaillierPk.HomoMul(ukc[en[0]], w1)
	v2U1StarCipher, _ := u2PaillierPk.Encrypt(vU1Star[k])
	u2Kw1Cipher = u2PaillierPk.HomoAdd(u2Kw1Cipher,v2U1StarCipher) // send to u2
	mp = []string{msgprex,cur_enode}
	enode = strings.Join(mp,"-")
	s0 = "MKW"
	s1 = string(u2Kw1Cipher.Bytes()) 
	ss = enode + sep + s0 + sep + s1
	log.Debug("================kg ec2 round four,send msg,code is MKW==================")
	p2pdcrm.SendMsgToPeer(enodes,ss)
    }

     _,cherr = GetChannelValue(ch_t,w.bmkg)
    if cherr != nil {
	log.Debug("get w.bmkg timeout.")
	var ret2 Err
	ret2.info = "get MKG timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    mkgs := make([]string,THRESHOLD-1)
    for i=0;i<(THRESHOLD-1);i++ {
	v,cherr := GetChannelValue(ch_t,w.msg_mkg)
	if cherr != nil {
	    log.Debug("get w.msg_mkg timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_mkg timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
	mkgs[i] = v
    }
    for _,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range mkgs {
	    mm := strings.Split(v, sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		kg := new(big.Int).SetBytes([]byte(mm[2]))
		mkg[en[0]] = kg
		break
	    }
	}
    }

    _,cherr = GetChannelValue(ch_t,w.bmkw)
    if cherr != nil {
	log.Debug("get w.bmkw timeout.")
	var ret2 Err
	ret2.info = "get MKW timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    mkws := make([]string,THRESHOLD-1)
    for i=0;i<(THRESHOLD-1);i++ {
	v,cherr := GetChannelValue(ch_t,w.msg_mkw)
	if cherr != nil {
	    log.Debug("get w.msg_mkw timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_mkw timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
	mkws[i] = v
    }
    for _,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range mkws {
	    mm := strings.Split(v, sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		kw := new(big.Int).SetBytes([]byte(mm[2]))
		mkw[en[0]] = kw
		break
	    }
	}
    }
    
    var index int
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	if IsCurNode(enodes,cur_enode) {
	    index = k
	    break
	}
    }

    u1PaillierSk := GetPaillierSk(save,index)
    if u1PaillierSk == nil {
	log.Debug("get paillier sk fail.")
	var ret2 Err
	ret2.info = "get paillier sk fail."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }
    
    alpha1 := make([]*big.Int,THRESHOLD)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	alpha1U1, _ := u1PaillierSk.Decrypt(mkg[en[0]])
	alpha1[k] = alpha1U1
    }

    uu1 := make([]*big.Int,THRESHOLD)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	u1U1, _ := u1PaillierSk.Decrypt(mkw[en[0]])
	uu1[k] = u1U1
    }

    delta1 := alpha1[0]
    for i=0;i<THRESHOLD;i++ {
	if i == 0 {
	    continue
	}
	delta1 = new(big.Int).Add(delta1,alpha1[i])
    }
    for i=0;i<THRESHOLD;i++ {
	delta1 = new(big.Int).Add(delta1, betaU1[i])
    }

    sigma1 := uu1[0]
    for i=0;i<THRESHOLD;i++ {
	if i == 0 {
	    continue
	}
	sigma1 = new(big.Int).Add(sigma1,uu1[i])
    }
    for i=0;i<THRESHOLD;i++ {
	sigma1 = new(big.Int).Add(sigma1, vU1[i])
    }

    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "DELTA1"
    zero,_ := new(big.Int).SetString("0",10)
    if delta1.Cmp(zero) < 0 { //bug
	s1 = "0" + sep12 + string(delta1.Bytes())
    } else {
	s1 = string(delta1.Bytes())
    }
    ss = enode + sep + s0 + sep + s1
    log.Debug("================sign ec2 round five,send msg,code is DELTA1==================")
    SendMsgToDcrmGroup(ss)

     _,cherr = GetChannelValue(ch_t,w.bdelta1)
    if cherr != nil {
	log.Debug("get w.bdelta1 timeout.")
	var ret2 Err
	ret2.info = "get DELTA1 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }
    
    var delta1s = make(map[string]*big.Int)
    delta1s[cur_enode] = delta1
    log.Debug("===========Sign_ec2,","delta1",delta1,"","===========")

    dels := make([]string,THRESHOLD-1)
    for i=0;i<(THRESHOLD-1);i++ {
	v,cherr := GetChannelValue(ch_t,w.msg_delta1)
	if cherr != nil {
	    log.Debug("get w.msg_delta1 timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_delta1 timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
	dels[i] = v
    }
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range dels {
	    mm := strings.Split(v, sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		tmps := strings.Split(mm[2], sep12)
		if len(tmps) == 2 {
		    del := new(big.Int).SetBytes([]byte(tmps[1]))
		    del = new(big.Int).Sub(zero,del)
		    log.Debug("===========Sign_ec2,","k",k,"del",del,"","===========")
		    delta1s[en[0]] = del
		} else {
		    del := new(big.Int).SetBytes([]byte(mm[2]))
		    log.Debug("===========Sign_ec2,","k",k,"del",del,"","===========")
		    delta1s[en[0]] = del
		}
		break
	    }
	}
    }
    
    var deltaSum *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	deltaSum = delta1s[en[0]]
	break
    }
    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	deltaSum = new(big.Int).Add(deltaSum,delta1s[en[0]])
    }
    deltaSum = new(big.Int).Mod(deltaSum, secp256k1.S256().N)

    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "D11"
    dlen := len(commitU1GammaG.D)
    s1 = strconv.Itoa(dlen)

    ss = enode + sep + s0 + sep + s1 + sep
    for _,d := range commitU1GammaG.D {
	ss += string(d.Bytes())
	ss += sep
    }
    ss = ss + "NULL"
    log.Debug("================sign ec2 round six,send msg,code is D11==================")
    SendMsgToDcrmGroup(ss)

    _,cherr = GetChannelValue(ch_t,w.bd11_1)
    if cherr != nil {
	log.Debug("get w.bd11_1 timeout in sign.")
	var ret2 Err
	ret2.info = "get D11 timeout in sign."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    d11s := make([]string,THRESHOLD-1)
    for i=0;i<(THRESHOLD-1);i++ {
	//v := <-w.msg_d1_1
	v,cherr := GetChannelValue(ch_t,w.msg_d11_1)
	if cherr != nil {
	    log.Debug("get w.msg_d11_1 timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_d11_1 timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
	d11s[i] = v
    }

    c11s := make([]string,THRESHOLD-1)
    for i=0;i<(THRESHOLD-1);i++ {
	v,cherr := GetChannelValue(ch_t,w.msg_c11)
	if cherr != nil {
	    log.Debug("get w.msg_c11 timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_c11 timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
	c11s[i] = v
    }

    var udecom = make(map[string]*commit.Commitment)
    for _,v := range c11s {
	mm := strings.Split(v, sep)
	prex := mm[0]
	prexs := strings.Split(prex,"-")
	for _,vv := range d11s {
	    mmm := strings.Split(vv, sep)
	    prex2 := mmm[0]
	    prexs2 := strings.Split(prex2,"-")
	    if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
		dlen,_ := strconv.Atoi(mmm[2])
		var gg = make([]*big.Int,0)
		l := 0
		for j:=0;j<dlen;j++ {
		    l++
		    gg = append(gg,new(big.Int).SetBytes([]byte(mmm[2+l])))
		}
		deCommit := &commit.Commitment{C:new(big.Int).SetBytes([]byte(mm[2])), D:gg}
		log.Debug("=========Sign_ec2,","deCommit",deCommit,"","==========")
		udecom[prexs[len(prexs)-1]] = deCommit
		break
	    }
	}
    }
    deCommit_commitU1GammaG := &commit.Commitment{C: commitU1GammaG.C, D: commitU1GammaG.D}
    udecom[cur_enode] = deCommit_commitU1GammaG
    log.Debug("=========Sign_ec2,","deCommit_commitU1GammaG",deCommit_commitU1GammaG,"","==========")

    log.Debug("===========Sign_ec2,[Signature Generation][Round 4] 2. all users verify commit(GammaG):=============")

    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if udecom[en[0]].Verify() == false {
	    log.Debug("u1 verify commit in sign fail.")
	    var ret2 Err
	    ret2.info = "u1 verify commit in sign fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
    }

    var ug = make(map[string][]*big.Int)
    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	_, u1GammaG := udecom[en[0]].DeCommit()
	ug[en[0]] = u1GammaG
    }

    var GammaGSumx *big.Int
    var GammaGSumy *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	GammaGSumx = (ug[en[0]])[0]
	GammaGSumy = (ug[en[0]])[1]
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	GammaGSumx, GammaGSumy = secp256k1.S256().Add(GammaGSumx, GammaGSumy, (ug[en[0]])[0],(ug[en[0]])[1])
    }
    log.Debug("========Sign_ec2,","GammaGSumx",GammaGSumx,"GammaGSumy",GammaGSumy,"","===========")
	
    deltaSumInverse := new(big.Int).ModInverse(deltaSum, secp256k1.S256().N)
    deltaGammaGx, deltaGammaGy := secp256k1.S256().ScalarMult(GammaGSumx, GammaGSumy, deltaSumInverse.Bytes())

    r := deltaGammaGx

    if r.Cmp(zero) == 0 {
	log.Debug("sign error: r equal zero.")
	var ret2 Err
	ret2.info = "sign error: r equal zero."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }
    
    mMtA,_ := new(big.Int).SetString(message,16)
    
    mk1 := new(big.Int).Mul(mMtA, u1K)
    rSigma1 := new(big.Int).Mul(deltaGammaGx, sigma1)
    us1 := new(big.Int).Add(mk1, rSigma1)
    us1 = new(big.Int).Mod(us1, secp256k1.S256().N)
    log.Debug("=========Sign_ec2,","us1",us1,"","==========")
    
    S1x, S1y := secp256k1.S256().ScalarMult(deltaGammaGx, deltaGammaGy, us1.Bytes())
    log.Debug("=========Sign_ec2,","S1x",S1x,"","==========")
    log.Debug("=========Sign_ec2,","S1y",S1y,"","==========")
    
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "S1"
    s1 = string(S1x.Bytes())
    s2 := string(S1y.Bytes())
    ss = enode + sep + s0 + sep + s1 + sep + s2
    log.Debug("================sign ec2 round seven,send msg,code is S1==================")
    SendMsgToDcrmGroup(ss)

    _,cherr = GetChannelValue(ch_t,w.bs1)
    if cherr != nil {
	log.Debug("get w.bs1 timeout in sign.")
	var ret2 Err
	ret2.info = "get S1 timeout in sign."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    var s1s = make(map[string][]*big.Int)
    s1ss := []*big.Int{S1x,S1y}
    s1s[cur_enode] = s1ss

    us1s := make([]string,THRESHOLD-1)
    for i=0;i<(THRESHOLD-1);i++ {
	v,cherr := GetChannelValue(ch_t,w.msg_s1)
	if cherr != nil {
	    log.Debug("get w.msg_s1 timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_s1 timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
	us1s[i] = v
    }
    for _,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range us1s {
	    mm := strings.Split(v, sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		x := new(big.Int).SetBytes([]byte(mm[2]))
		y := new(big.Int).SetBytes([]byte(mm[3]))
		tmp := []*big.Int{x,y}
		s1s[en[0]] = tmp
		break
	    }
	}
    }

    var SAllx *big.Int
    var SAlly *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	SAllx = (s1s[en[0]])[0]
	SAlly = (s1s[en[0]])[1]
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	SAllx, SAlly = secp256k1.S256().Add(SAllx, SAlly, (s1s[en[0]])[0],(s1s[en[0]])[1])
    }
    log.Debug("[Signature Generation][Test] verify SAll ?= m*G + r*PK:")
    log.Debug("========Sign_ec2,","SAllx",SAllx,"SAlly",SAlly,"","===========")
	
    mMtAGx, mMtAGy := secp256k1.S256().ScalarBaseMult(mMtA.Bytes())
    rMtAPKx, rMtAPKy := secp256k1.S256().ScalarMult(pkx, pky, deltaGammaGx.Bytes())
    SAllComputex, SAllComputey := secp256k1.S256().Add(mMtAGx, mMtAGy, rMtAPKx, rMtAPKy)
    log.Debug("========Sign_ec2,","SAllComputex",SAllComputex,"SAllComputey",SAllComputey,"","===========")

    if SAllx.Cmp(SAllComputex) != 0 || SAlly.Cmp(SAllComputey) != 0 {
	log.Debug("verify SAll != m*G + r*PK in sign ec2.")
	var ret2 Err
	ret2.info = "verify SAll != m*G + r*PK in dcrm sign ec2."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "SS1"
    s1 = string(us1.Bytes())
    ss = enode + sep + s0 + sep + s1
    log.Debug("================sign ec2 round eight,send msg,code is SS1==================")
    SendMsgToDcrmGroup(ss)

    _,cherr = GetChannelValue(ch_t,w.bss1)
    if cherr != nil {
	log.Debug("get w.bss1 timeout in sign.")
	var ret2 Err
	ret2.info = "get SS1 timeout in sign."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    var ss1s = make(map[string]*big.Int)
    ss1s[cur_enode] = us1

    uss1s := make([]string,THRESHOLD-1)
    for i=0;i<(THRESHOLD-1);i++ {
	v,cherr := GetChannelValue(ch_t,w.msg_ss1)
	if cherr != nil {
	    log.Debug("get w.msg_ss1 timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_ss1 timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
	uss1s[i] = v
    }
    for _,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range uss1s {
	    mm := strings.Split(v, sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		tmp := new(big.Int).SetBytes([]byte(mm[2]))
		ss1s[en[0]] = tmp
		break
	    }
	}
    }

    var sSum *big.Int
    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	sSum = ss1s[en[0]]
	break
    }

    for k,id := range ids {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	sSum = new(big.Int).Add(sSum,ss1s[en[0]])
    }
    sSum = new(big.Int).Mod(sSum, secp256k1.S256().N) 
   
    bb := false
    halfN := new(big.Int).Div(secp256k1.S256().N, big.NewInt(2))
    if sSum.Cmp(halfN) > 0 {
	bb = true
	sSum = new(big.Int).Sub(secp256k1.S256().N, sSum)
    }

    s := sSum
    if s.Cmp(zero) == 0 {
	log.Debug("sign error: s equal zero.")
	var ret2 Err
	ret2.info = "sign error: s equal zero."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    log.Debug("==========Sign_ec2,","r",r,"===============")
    log.Debug("==========Sign_ec2,","s",s,"===============")
    
    sSumInverse := new(big.Int).ModInverse(sSum, secp256k1.S256().N)
    mMtASInverse := new(big.Int).Mul(mMtA, sSumInverse)
    mMtASInverse = new(big.Int).Mod(mMtASInverse, secp256k1.S256().N)

    mMtASInverseGx, mMtASInverseGy := secp256k1.S256().ScalarBaseMult(mMtASInverse.Bytes())
    rSSumInverse := new(big.Int).Mul(deltaGammaGx, sSumInverse)
    rSSumInverse = new(big.Int).Mod(rSSumInverse, secp256k1.S256().N)

    rSSumInversePkx, rSSumInversePky := secp256k1.S256().ScalarMult(pkx, pky, rSSumInverse.Bytes())
    computeRxMtA, computeRyMtA := secp256k1.S256().Add(mMtASInverseGx, mMtASInverseGy, rSSumInversePkx, rSSumInversePky) // m * sInverse * base point + r * sInverse * PK
    log.Debug("==========Sign_ec2,","computeRxMtA",computeRxMtA,"===============")
    if r.Cmp(computeRxMtA) != 0 {
	log.Debug("verify r != R.x in dcrm sign ec2.")
	var ret2 Err
	ret2.info = "verify r != R.x in dcrm sign ec2."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    signature := new(ECDSASignature)
    signature.New()
    signature.SetR(r)
    signature.SetS(s)

    //v
    recid := secp256k1.Get_ecdsa_sign_v(computeRxMtA,computeRyMtA)
    if tokenType == "ETH" && bb {
	//s = new(big.Int).Sub(secp256k1.S256().N,s)
	//signature.setS(s)
	recid ^=1
    }
    if tokenType == "BTC" && bb {
	//s = new(big.Int).Sub(secp256k1.S256().N,s)
	//signature.setS(s);
	recid ^= 1
    }
    signature.SetRecoveryParam(int32(recid))

    //===================================================
    if Verify(signature.GetR(),signature.GetS(),signature.GetRecoveryParam(),message,pkx,pky) == false {
	log.Debug("===================dcrm sign,verify is false=================")
	var ret2 Err
	ret2.info = "sign verfify fail."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    signature2 := GetSignString(signature.GetR(),signature.GetS(),signature.GetRecoveryParam(),int(signature.GetRecoveryParam()))
    log.Debug("======================","r",signature.GetR(),"","=============================")
    log.Debug("======================","s",signature.GetS(),"","=============================")
    log.Debug("======================","signature str",signature2,"","=============================")
    res := RpcDcrmRes{ret:signature2,err:nil}
    ch <- res
}

func GetPaillierPk(save string,index int) *paillier.PublicKey {
    if save == "" || index < 0 {
	return nil
    }

    mm := strings.Split(save, sep11)
    s := 4 + 4*index
    l := mm[s]
    n := new(big.Int).SetBytes([]byte(mm[s+1]))
    g := new(big.Int).SetBytes([]byte(mm[s+2]))
    n2 := new(big.Int).SetBytes([]byte(mm[s+3]))
    publicKey := &paillier.PublicKey{Length: l, N: n, G: g, N2: n2}
    return publicKey
}

func GetPaillierSk(save string,index int) *paillier.PrivateKey {
    publicKey := GetPaillierPk(save,index)
    if publicKey != nil {
	mm := strings.Split(save, sep11)
	l := mm[1]
	ll := new(big.Int).SetBytes([]byte(mm[2]))
	uu := new(big.Int).SetBytes([]byte(mm[3]))
	privateKey := &paillier.PrivateKey{Length: l, PublicKey: *publicKey, L: ll, U: uu}
	return privateKey
    }

    return nil
}

