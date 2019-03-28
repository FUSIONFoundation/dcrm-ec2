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
	"sync"
	"encoding/json"
	"strconv"
	"bytes"
	"context"
	"time"
	"github.com/fusion/go-fusion/rpc"
	"github.com/fusion/go-fusion/common/hexutil"
	"github.com/fusion/go-fusion/ethclient"
	"encoding/hex"
	"github.com/fusion/go-fusion/log"
	"github.com/syndtr/goleveldb/leveldb"
	"os/exec"
	"github.com/fusion/go-fusion/common/math/random"
	"github.com/fusion/go-fusion/crypto/sha3"
	"github.com/fusion/go-fusion/crypto/dcrm/ec2/schnorrZK"
	"github.com/fusion/go-fusion/crypto/dcrm/ec2/MtAZK"
	"sort"
)
////////////

var (
    tmp2 string
    sep = "dcrmparm"
    sep2 = "dcrmmsg"
    sep9 = "dcrmsep9" //valatetx
    sep10 = "dcrmsep10" //valatetx
    sep11 = "dcrmsep11"
    sep12 = "dcrmsep12"
    msgtypesep = "caihaijundcrm"
    lock sync.Mutex
    
    FSN      Backend

    dir string//dir,_= ioutil.TempDir("", "dcrmkey")
    NodeCnt = 3
    ThresHold = 3
    PaillierKeyLength = 2048

    CHAIN_ID       = 4 //ethereum mainnet=1 rinkeby testnet=4  //TODO :get user define chainid.

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

func GetChannelValue(t int,obj interface{}) (string,error) {
    timeout := make(chan bool, 1)
    go func(timeout chan bool) {
	 time.Sleep(time.Duration(t)*time.Second) //1000 == 1s
	 timeout <- true
     }(timeout)

     switch obj.(type) {
	 case chan interface{} :
	     ch := obj.(chan interface{})
	     select {
		 case v := <- ch :
		     ret,ok := v.(RpcDcrmRes)
		     if ok == true {
			    if ret.ret != "" {
				return ret.ret,nil
			    } else {
				return "",ret.err
			    }
		     }
		 case <- timeout :
		     return "",errors.New("get rpc result time out")
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
    res <-false 
    return 
    /*if strings.EqualFold(cointype,"ETH") || strings.EqualFold(cointype,"BTC") {
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
	   
	    //TODO
	    vv := DcrmLockin{Tx:"xxx"+"-"+va+"-"+cointype,LockinAddr:to,Hashkey:hashkey,RealDcrmFrom:realdcrmfrom}
	    if _,err = Validate_Txhash(&vv);err != nil {
		    log.Debug("=============MergeDcrmBalance,validate fail.==============")
		res <-false 
		return
	    }

	    res <-true
	    return
	}*/
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
	case "rpc_req_dcrmaddr":
	    m := strings.Split(msg,sep9)
	    v := ReqAddrSendMsgToDcrm{Fusionaddr:m[0],Pub:m[1],Cointype:m[2]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_confirm_dcrmaddr":
	    m := strings.Split(msg,sep9)
	    v := ConfirmAddrSendMsgToDcrm{Txhash:m[0],Tx:m[1],FusionAddr:m[2],DcrmAddr:m[3],Hashkey:m[4],Cointype:m[5]}
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

///////////////////////////////////////
type WorkReq interface {
    Run(workid int,ch chan interface{}) bool
}

//RecvMsg
type RecvMsg struct {
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
	mmm := strings.Split(mm[0],sep)
	prex := mmm[0]
	types.SetDcrmRpcWorkersData(prex,strconv.Itoa(workid))

	//bug
	val,ok := GetLockoutInfoFromLocalDB(mmm[1])
	if ok == nil && val != "" {
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

    return true 
}

////////////////////////////////////////////
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
    //
    msg_c1 chan string
    msg_kc chan string
    msg_mkg chan string
    msg_mkw chan string
    msg_delta1 chan string
    msg_d1_1 chan string
    msg_share1 chan string
    msg_zkfact chan string
    msg_zku chan string
    msg_mtazk1proof chan string
    bc1 chan bool
    bmkg chan bool
    bmkw chan bool
    bdelta1 chan bool
    bd1_1 chan bool
    bshare1 chan bool
    bzkfact chan bool
    bzku chan bool
    bmtazk1proof chan bool
    msg_c11 chan string
    msg_d11_1 chan string
    msg_s1 chan string
    msg_ss1 chan string
    bkc chan bool
    bs1 chan bool
    bss1 chan bool
    bc11 chan bool
    bd11_1 chan bool
    //
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
    msg_share1:make(chan string,NodeCnt-1),
    msg_zkfact:make(chan string,NodeCnt-1),
    msg_zku:make(chan string,NodeCnt-1),
    msg_mtazk1proof:make(chan string,ThresHold-1),
    bshare1:make(chan bool,1),
    bzkfact:make(chan bool,1),
    bzku:make(chan bool,1),
    bmtazk1proof:make(chan bool,1),
    msg_c1:make(chan string,NodeCnt-1),
    msg_d1_1:make(chan string,NodeCnt-1),
    msg_c11:make(chan string,ThresHold-1),
    msg_kc:make(chan string,ThresHold-1),
    msg_mkg:make(chan string,ThresHold-1),
    msg_mkw:make(chan string,ThresHold-1),
    msg_delta1:make(chan string,ThresHold-1),
    msg_d11_1:make(chan string,ThresHold-1),
    msg_s1:make(chan string,ThresHold-1),
    msg_ss1:make(chan string,ThresHold-1),
    pkx:make(chan string,1),
    pky:make(chan string,1),
    save:make(chan string,1),
    bc1:make(chan bool,1),
    bd1_1:make(chan bool,1),
    bc11:make(chan bool,1),
    bkc:make(chan bool,1),
    bs1:make(chan bool,1),
    bss1:make(chan bool,1),
    bmkg:make(chan bool,1),
    bmkw:make(chan bool,1),
    bdelta1:make(chan bool,1),
    bd11_1:make(chan bool,1),
    }
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
	
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	log.Root().SetHandler(glogger)

	erc20_client = nil
	BTC_BLOCK_CONFIRMS = 1
	BTC_DEFAULT_FEE = 0.0005
	ETH_DEFAULT_FEE,_ = new(big.Int).SetString("10000000000000000",10)
	rpcs,_ = new(big.Int).SetString("0",10)
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
    BlockTime  int64
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
    if cnt <= 0 || enode == "" {
	return false
    }

    nodes := strings.Split(enode,sep2)
    for _,node := range nodes {
	node2, _ := discover.ParseNode(node)
	if node2.ID.String() == cur_enode {
	    return true
	}
    }

    return false
}

func Validate_Txhash(wr WorkReq) (string,error) {

    //////////
    if IsInGroup() == false {
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

    res := RpcDcrmRes{ret:stmp,err:nil}
    ch <- res

    db.Close()
    lock.Unlock()
    if stmp != "" {
	WriteDcrmAddrToLocalDB(fusionaddr,cointype,stmp)
    }
}

func GetTxHashForLockout(realfusionfrom string,realdcrmfrom string,to string,value string,cointype string,signature string) (string,string,error) {

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
    dcrm_sign(msgprex,"xxx",signer.Hash(lockoutx).String(),realdcrmfrom,cointype,rch)
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
	    if len(w.msg_c1) == (NodeCnt-1) {
		w.bc1 <- true
	    }
	case "D1":
	    w.msg_d1_1 <-msg
	    if len(w.msg_d1_1) == (NodeCnt-1) {
		w.bd1_1 <- true
	    }
	case "SHARE1":
	    w.msg_share1 <-msg
	    if len(w.msg_share1) == (NodeCnt-1) {
		w.bshare1 <- true
	    }
	case "ZKFACTPROOF":
	    w.msg_zkfact <-msg
	    if len(w.msg_zkfact) == (NodeCnt-1) {
		w.bzkfact <- true
	    }
	case "ZKUPROOF":
	    w.msg_zku <-msg
	    if len(w.msg_zku) == (NodeCnt-1) {
		w.bzku <- true
	    }
	case "MTAZK1PROOF":
	    w.msg_mtazk1proof <-msg
	    if len(w.msg_mtazk1proof) == (ThresHold-1) {
		w.bmtazk1proof <- true
	    }
	    //sign
       case "C11":
	    w.msg_c11 <-msg
	    if len(w.msg_c11) == (ThresHold-1) {
		w.bc11 <- true
	    }
       case "KC":
	    w.msg_kc <-msg
	    if len(w.msg_kc) == (ThresHold-1) {
		w.bkc <- true
	    }
       case "MKG":
	    w.msg_mkg <-msg
	    if len(w.msg_mkg) == (ThresHold-1) {
		w.bmkg <- true
	    }
       case "MKW":
	    w.msg_mkw <-msg
	    if len(w.msg_mkw) == (ThresHold-1) {
		w.bmkw <- true
	    }
       case "DELTA1":
	    w.msg_delta1 <-msg
	    if len(w.msg_delta1) == (ThresHold-1) {
		w.bdelta1 <- true
	    }
	case "D11":
	    w.msg_d11_1 <-msg
	    if len(w.msg_d11_1) == (ThresHold-1) {
		w.bd11_1 <- true
	    }
	case "S1":
	    w.msg_s1 <-msg
	    if len(w.msg_s1) == (ThresHold-1) {
		w.bs1 <- true
	    }
	case "SS1":
	    w.msg_ss1 <-msg
	    if len(w.msg_ss1) == (ThresHold-1) {
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
	    _,ok := types.GetDcrmRpcMsgDataKReady(prex)
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
//==========================================================

type AccountListJson struct {
    ACCOUNTLIST []AccountListInfo
}

type AccountListInfo struct {
    COINTYPE string
    DCRMADDRESS string
    DCRMPUBKEY string
}
//============================================================
func Dcrm_LiLoReqAddress(wr WorkReq) (string, error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    ret,cherr := GetChannelValue(ch_t,rch)
    if cherr != nil {
	log.Debug("Dcrm_LiLoReqAddress timeout.")
	return "",errors.New("Dcrm_LiLoReqAddress timeout.")
    }
    return ret,cherr
}

func Dcrm_Sign(wr WorkReq) (string,error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    ret,cherr := GetChannelValue(ch_t,rch)
    if cherr != nil {
	log.Debug("Dcrm_Sign get timeout.")
	log.Debug(cherr.Error())
	return "",cherr
    }
    return ret,cherr
    //rpc-req
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
    if ns != NodeCnt {
	var ret2 Err
	ret2.info = "get nodes info error in keygenerate."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }

    //1. generate their own "partial" private key secretly
    u1 := random.GetRandomIntFromZn(secp256k1.S256().N)

    // 2. calculate "partial" public key, make "pritial" public key commiment to get (C,D)
    u1Gx, u1Gy := secp256k1.S256().ScalarBaseMult(u1.Bytes())
    commitU1G := new(commit.Commitment).Commit(u1Gx, u1Gy)

    // 3. generate their own paillier public key and private key
    u1PaillierPk, u1PaillierSk := paillier.GenerateKeyPair(PaillierKeyLength)

    // 4. Broadcast
    // commitU1G.C, commitU2G.C, commitU3G.C, commitU4G.C, commitU5G.C
    // u1PaillierPk, u2PaillierPk, u3PaillierPk, u4PaillierPk, u5PaillierPk
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

    // 1. Receive Broadcast
    // commitU1G.C, commitU2G.C, commitU3G.C, commitU4G.C, commitU5G.C
    // u1PaillierPk, u2PaillierPk, u3PaillierPk, u4PaillierPk, u5PaillierPk
     _,cherr := GetChannelValue(ch_t,w.bc1)
    if cherr != nil {
	log.Debug("get w.bc1 timeout.")
	var ret2 Err
	ret2.info = "get C1 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }

    // 2. generate their vss to get shares which is a set
    // [notes]
    // all nodes has their own id, in practival, we can take it as double hash of public key of fusion

    ids := GetIds()

    u1PolyG, _, u1Shares, err := vss.Vss(u1, ids, ThresHold, NodeCnt)
    if err != nil {
	res := RpcDcrmRes{ret:"",err:err}
	ch <- res
	return false 
    }

    // 3. send the the proper share to proper node 
    //example for u1:
    // Send u1Shares[0] to u1
    // Send u1Shares[1] to u2
    // Send u1Shares[2] to u3
    // Send u1Shares[3] to u4
    // Send u1Shares[4] to u5
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

    // 4. Broadcast
    // commitU1G.D, commitU2G.D, commitU3G.D, commitU4G.D, commitU5G.D
    // u1PolyG, u2PolyG, u3PolyG, u4PolyG, u5PolyG
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

    // 1. Receive Broadcast
    // commitU1G.D, commitU2G.D, commitU3G.D, commitU4G.D, commitU5G.D
    // u1PolyG, u2PolyG, u3PolyG, u4PolyG, u5PolyG
    _,cherr = GetChannelValue(ch_t,w.bd1_1)
    if cherr != nil {
	log.Debug("get w.bd1_1 timeout in keygenerate.")
	var ret2 Err
	ret2.info = "get D1 timeout in keygenerate."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }

    // 2. Receive Personal Data
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
    shares := make([]string,NodeCnt-1)
    for i=0;i<(NodeCnt-1);i++ {
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

    ds := make([]string,NodeCnt-1)
    for i=0;i<(NodeCnt-1);i++ {
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

    // 3. verify the share
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

    // 4.verify and de-commitment to get uG
    // for all nodes, construct the commitment by the receiving C and D
    cs := make([]string,NodeCnt-1)
    for i=0;i<(NodeCnt-1);i++ {
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

    // for all nodes, verify the commitment
    log.Debug("[Key Generation ec2][Round 3] 4. all nodes verify commit:")
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

    // for all nodes, de-commitment
    var ug = make(map[string][]*big.Int)
    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	_, u1G := udecom[en[0]].DeCommit()
	ug[en[0]] = u1G
    }

    // for all nodes, calculate the public key
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

    // 5. calculate the share of private key
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

    //save skU1/u1PaillierSk/u1PaillierPk/...
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

    sstmp := ss //////
    tmp := ss

    ss = ss + "NULL"

    // 6. calculate the zk
    // ## add content: zk of paillier key, zk of u
    
    // zk of paillier key
    u1zkFactProof := u1PaillierSk.ZkFactProve()
    // zk of u
    u1zkUProof := schnorrZK.ZkUProve(u1)

    // 7. Broadcast zk
    // u1zkFactProof, u2zkFactProof, u3zkFactProof, u4zkFactProof, u5zkFactProof
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "ZKFACTPROOF"
    s1 = string(u1zkFactProof.H1.Bytes())
    s2 = string(u1zkFactProof.H2.Bytes())
    s3 = string(u1zkFactProof.Y.Bytes())
    s4 = string(u1zkFactProof.E.Bytes())
    s5 = string(u1zkFactProof.N.Bytes())
    ss = enode + sep + s0 + sep + s1 + sep + s2 + sep + s3 + sep + s4 + sep + s5
    log.Debug("================kg ec2 round three,send msg,code is ZKFACTPROOF==================")
    SendMsgToDcrmGroup(ss)

    // 1. Receive Broadcast zk
    // u1zkFactProof, u2zkFactProof, u3zkFactProof, u4zkFactProof, u5zkFactProof
    _,cherr = GetChannelValue(ch_t,w.bzkfact)
    if cherr != nil {
	log.Debug("get w.bzkfact timeout in keygenerate.")
	var ret2 Err
	ret2.info = "get ZKFACTPROOF timeout in keygenerate."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }

    sstmp2 := s1 + sep11 + s2 + sep11 + s3 + sep11 + s4 + sep11 + s5

    // 8. Broadcast zk
    // u1zkUProof, u2zkUProof, u3zkUProof, u4zkUProof, u5zkUProof
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "ZKUPROOF"
    s1 = string(u1zkUProof.E.Bytes())
    s2 = string(u1zkUProof.S.Bytes())
    ss = enode + sep + s0 + sep + s1 + sep + s2
    log.Debug("================kg ec2 round three,send msg,code is ZKUPROOF==================")
    SendMsgToDcrmGroup(ss)

    // 9. Receive Broadcast zk
    // u1zkUProof, u2zkUProof, u3zkUProof, u4zkUProof, u5zkUProof
    _,cherr = GetChannelValue(ch_t,w.bzku)
    if cherr != nil {
	log.Debug("get w.bzku timeout in keygenerate.")
	var ret2 Err
	ret2.info = "get ZKUPROOF timeout in keygenerate."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }
    
    // 1. verify the zk
    // ## add content: verify zk of paillier key, zk of u
	
    // for all nodes, verify zk of paillier key
    zkfacts := make([]string,NodeCnt-1)
    for i=0;i<(NodeCnt-1);i++ {
	v,cherr := GetChannelValue(ch_t,w.msg_zkfact)
	if cherr != nil {
	    log.Debug("get w.msg_zkfact timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_zkfact timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
    
	    return false
	}
	zkfacts[i] = v
    }

    for k,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) { /////bug for save zkfact
	    sstmp = sstmp + sstmp2 + sep11
	    continue
	}

	u1PaillierPk2 := GetPaillierPk(tmp,k)
	for _,v := range zkfacts {
	    mm := strings.Split(v, sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		h1 := new(big.Int).SetBytes([]byte(mm[2]))
		h2 := new(big.Int).SetBytes([]byte(mm[3]))
		y := new(big.Int).SetBytes([]byte(mm[4]))
		e := new(big.Int).SetBytes([]byte(mm[5]))
		n := new(big.Int).SetBytes([]byte(mm[6]))
		zkFactProof := &paillier.ZkFactProof{H1: h1, H2: h2, Y: y, E: e,N:n}
		log.Debug("===============KeyGenerate_ec2,","zkFactProof",zkFactProof,"","=============")
		///////
		sstmp = sstmp + mm[2] + sep11 + mm[3] + sep11 + mm[4] + sep11 + mm[5] + sep11 + mm[6] + sep11  ///for save zkfact
		//////

		if !u1PaillierPk2.ZkFactVerify(zkFactProof) {
		    log.Debug("zk fact verify fail in keygenerate.")
		    var ret2 Err
		    ret2.info = "zk fact verify fail in keygenerate."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
	    
		    return false 
		}

		break
	    }
	}
    }

    // for all nodes, verify zk of u
    zku := make([]string,NodeCnt-1)
    for i=0;i<(NodeCnt-1);i++ {
	v,cherr := GetChannelValue(ch_t,w.msg_zku)
	if cherr != nil {
	    log.Debug("get w.msg_zku timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_zku timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return false
	}
	zku[i] = v
    }

    for _,id := range ids {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	for _,v := range zku {
	    mm := strings.Split(v, sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		e := new(big.Int).SetBytes([]byte(mm[2]))
		s := new(big.Int).SetBytes([]byte(mm[3]))
		zkUProof := &schnorrZK.ZkUProof{E: e, S: s}
		if !schnorrZK.ZkUVerify(ug[en[0]],zkUProof) {
		    log.Debug("zku verify fail in keygenerate.")
		    var ret2 Err
		    ret2.info = "zku verify fail in keygenerate."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return false 
		}

		break
	    }
	}
    } 
    
    sstmp = sstmp + "NULL"
    w.save <- sstmp

    return true
}

func Sign_ec2(msgprex string,save string,message string,tokenType string,pkx *big.Int,pky *big.Int,ch chan interface{},id int) {
    log.Debug("===================Sign_ec2====================")
    w := workers[id]
    
    // [Notes]
    // 1. assume the nodes who take part in the signature generation as follows
    ids := GetIds()
    idSign := ids[:ThresHold]
	
    // 1. map the share of private key to no-threshold share of private key
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
    
    // 2. select k and gamma randomly
    u1K := random.GetRandomIntFromZn(secp256k1.S256().N)
    u1Gamma := random.GetRandomIntFromZn(secp256k1.S256().N)
    
    // 3. make gamma*G commitment to get (C, D)
    u1GammaGx,u1GammaGy := secp256k1.S256().ScalarBaseMult(u1Gamma.Bytes())
    commitU1GammaG := new(commit.Commitment).Commit(u1GammaGx, u1GammaGy)

    // 4. Broadcast
    //	commitU1GammaG.C, commitU2GammaG.C, commitU3GammaG.C
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "C11"
    s1 := string(commitU1GammaG.C.Bytes())
    ss := enode + sep + s0 + sep + s1
    log.Debug("================sign ec2 round one,send msg,code is C11==================")
    SendMsgToDcrmGroup(ss)

    // 1. Receive Broadcast
    //	commitU1GammaG.C, commitU2GammaG.C, commitU3GammaG.C
     _,cherr := GetChannelValue(ch_t,w.bc11)
    if cherr != nil {
	log.Debug("get w.bc11 timeout.")
	var ret2 Err
	ret2.info = "get C11 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }
    
    // 2. MtA(k, gamma) and MtA(k, w)
    // 2.1 encrypt c_k = E_paillier(k)
    var ukc = make(map[string]*big.Int)
    var ukc2 = make(map[string]*big.Int)
    var ukc3 = make(map[string]*paillier.PublicKey)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1KCipher,u1R,_ := u1PaillierPk.Encrypt(u1K)
	    ukc[en[0]] = u1KCipher
	    ukc2[en[0]] = u1R
	    ukc3[en[0]] = u1PaillierPk
	    break
	}
    }

    // 2.2 calculate zk(k)
    var zk1proof = make(map[string]*MtAZK.MtAZK1Proof)
    var zkfactproof = make(map[string]*paillier.ZkFactProof)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	u1zkFactProof := GetZkFactProof(save,k)
	zkfactproof[en[0]] = u1zkFactProof
	if IsCurNode(enodes,cur_enode) {
	    u1u1MtAZK1Proof := MtAZK.MtAZK1Prove(u1K,ukc2[en[0]], ukc3[en[0]], u1zkFactProof)
	    zk1proof[en[0]] = u1u1MtAZK1Proof
	} else {
	    u1u1MtAZK1Proof := MtAZK.MtAZK1Prove(u1K,ukc2[cur_enode], ukc3[cur_enode], u1zkFactProof)
	    //zk1proof[en[0]] = u1u1MtAZK1Proof
	    mp := []string{msgprex,cur_enode}
	    enode := strings.Join(mp,"-")
	    s0 := "MTAZK1PROOF"
	    s1 := string(u1u1MtAZK1Proof.Z.Bytes()) 
	    s2 := string(u1u1MtAZK1Proof.U.Bytes()) 
	    s3 := string(u1u1MtAZK1Proof.W.Bytes()) 
	    s4 := string(u1u1MtAZK1Proof.S.Bytes()) 
	    s5 := string(u1u1MtAZK1Proof.S1.Bytes()) 
	    s6 := string(u1u1MtAZK1Proof.S2.Bytes()) 
	    ss := enode + sep + s0 + sep + s1 + sep + s2 + sep + s3 + sep + s4 + sep + s5 + sep + s6
	    log.Debug("================sign ec2 round two,send msg,code is MTAZK1PROOF==================")
	    p2pdcrm.SendMsgToPeer(enodes,ss)
	}
    }

    _,cherr = GetChannelValue(ch_t,w.bmtazk1proof)
    if cherr != nil {
	log.Debug("get w.bmtazk1proof timeout in sign.")
	var ret2 Err
	ret2.info = "get MTAZK1PROOF timeout in sign."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    // 2.3 Broadcast c_k, zk(k)
    // u1KCipher, u2KCipher, u3KCipher
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "KC"
    s1 = string(ukc[cur_enode].Bytes())
    ss = enode + sep + s0 + sep + s1
    log.Debug("================sign ec2 round two,send msg,code is KC==================")
    SendMsgToDcrmGroup(ss)

    // 2.4 Receive Broadcast c_k, zk(k)
    // u1KCipher, u2KCipher, u3KCipher
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
    kcs := make([]string,ThresHold-1)
    for i=0;i<(ThresHold-1);i++ {
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
   
    // example for u1, receive: u1u1MtAZK1Proof from u1, u2u1MtAZK1Proof from u2, u3u1MtAZK1Proof from u3
    mtazk1s := make([]string,ThresHold-1)
    for i=0;i<(ThresHold-1);i++ {
	v,cherr := GetChannelValue(ch_t,w.msg_mtazk1proof)
	if cherr != nil {
	    log.Debug("get w.msg_mtazk1proof timeout.")
	    var ret2 Err
	    ret2.info = "get w.msg_mtazk1proof timeout."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
	mtazk1s[i] = v
    }

    for _,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    continue
	}
	for _,v := range mtazk1s {
	    mm := strings.Split(v, sep)
	    prex := mm[0]
	    prexs := strings.Split(prex,"-")
	    if prexs[len(prexs)-1] == en[0] {
		z := new(big.Int).SetBytes([]byte(mm[2]))
		u := new(big.Int).SetBytes([]byte(mm[3]))
		w := new(big.Int).SetBytes([]byte(mm[4]))
		s := new(big.Int).SetBytes([]byte(mm[5]))
		s1 := new(big.Int).SetBytes([]byte(mm[6]))
		s2 := new(big.Int).SetBytes([]byte(mm[7]))
		mtAZK1Proof := &MtAZK.MtAZK1Proof{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
		zk1proof[en[0]] = mtAZK1Proof
		break
	    }
	}
    }

    // 2.5 verify zk(k)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1rlt1 := zk1proof[cur_enode].MtAZK1Verify(ukc[cur_enode],ukc3[cur_enode],zkfactproof[cur_enode])
	    if !u1rlt1 {
		log.Debug("zero knowledge verify fail.")
		var ret2 Err
		ret2.info = "zero knowledge verify fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }
	} else {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1rlt1 := zk1proof[en[0]].MtAZK1Verify(ukc[en[0]],u1PaillierPk,zkfactproof[cur_enode])
	    if !u1rlt1 {
		log.Debug("zero knowledge verify fail.")
		var ret2 Err
		ret2.info = "zero knowledge verify fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }
	}
    }

    // 2.6
    // select betaStar randomly, and calculate beta, MtA(k, gamma)
    // select betaStar randomly, and calculate beta, MtA(k, w)
    
    // [Notes]
    // 1. betaStar is in [1, paillier.N - secp256k1.N^2]
    NSalt := new(big.Int).Lsh(big.NewInt(1), uint(PaillierKeyLength-PaillierKeyLength/10))
    NSubN2 := new(big.Int).Mul(secp256k1.S256().N, secp256k1.S256().N)
    NSubN2 = new(big.Int).Sub(NSalt, NSubN2)
    // 2. MinusOne
    MinusOne := big.NewInt(-1)
    
    betaU1Star := make([]*big.Int,ThresHold)
    betaU1 := make([]*big.Int,ThresHold)
    for i=0;i<ThresHold;i++ {
	beta1U1Star := random.GetRandomIntFromZn(NSubN2)
	beta1U1 := new(big.Int).Mul(MinusOne, beta1U1Star)
	betaU1Star[i] = beta1U1Star
	betaU1[i] = beta1U1
    }

    vU1Star := make([]*big.Int,ThresHold)
    vU1 := make([]*big.Int,ThresHold)
    for i=0;i<ThresHold;i++ {
	v1U1Star := random.GetRandomIntFromZn(NSubN2)
	v1U1 := new(big.Int).Mul(MinusOne, v1U1Star)
	vU1Star[i] = v1U1Star
	vU1[i] = v1U1
    }

    // 2.7
    // send c_kGamma to proper node, MtA(k, gamma)   zk
    var mkg = make(map[string]*big.Int)
    var mkg_mtazk2 = make(map[string]*MtAZK.MtAZK2Proof)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1KGamma1Cipher := u1PaillierPk.HomoMul(ukc[en[0]], u1Gamma)
	    beta1U1StarCipher, u1BetaR1,_ := u1PaillierPk.Encrypt(betaU1Star[k])
	    u1KGamma1Cipher = u1PaillierPk.HomoAdd(u1KGamma1Cipher, beta1U1StarCipher) // send to u1
	    u1u1MtAZK2Proof := MtAZK.MtAZK2Prove(u1Gamma, betaU1Star[k], u1BetaR1, ukc[cur_enode],ukc3[cur_enode], zkfactproof[cur_enode])
	    mkg[en[0]] = u1KGamma1Cipher
	    mkg_mtazk2[en[0]] = u1u1MtAZK2Proof
	    continue
	}
	
	u2PaillierPk := GetPaillierPk(save,k)
	u2KGamma1Cipher := u2PaillierPk.HomoMul(ukc[en[0]], u1Gamma)
	beta2U1StarCipher, u2BetaR1,_ := u2PaillierPk.Encrypt(betaU1Star[k])
	u2KGamma1Cipher = u2PaillierPk.HomoAdd(u2KGamma1Cipher, beta2U1StarCipher) // send to u2
	u2u1MtAZK2Proof := MtAZK.MtAZK2Prove(u1Gamma, betaU1Star[k], u2BetaR1, ukc[en[0]],u2PaillierPk,zkfactproof[cur_enode])
	mp = []string{msgprex,cur_enode}
	enode = strings.Join(mp,"-")
	s0 = "MKG"
	s1 = string(u2KGamma1Cipher.Bytes()) 
	//////
	s2 := string(u2u1MtAZK2Proof.Z.Bytes())
	s3 := string(u2u1MtAZK2Proof.ZBar.Bytes())
	s4 := string(u2u1MtAZK2Proof.T.Bytes())
	s5 := string(u2u1MtAZK2Proof.V.Bytes())
	s6 := string(u2u1MtAZK2Proof.W.Bytes())
	s7 := string(u2u1MtAZK2Proof.S.Bytes())
	s8 := string(u2u1MtAZK2Proof.S1.Bytes())
	s9 := string(u2u1MtAZK2Proof.S2.Bytes())
	s10 := string(u2u1MtAZK2Proof.T1.Bytes())
	s11 := string(u2u1MtAZK2Proof.T2.Bytes())
	///////
	ss = enode + sep + s0 + sep + s1 + sep + s2 + sep + s3 + sep + s4 + sep + s5 + sep + s6 + sep + s7 + sep + s8 + sep + s9 + sep + s10 + sep + s11
	log.Debug("================kg ec2 round three,send msg,code is MKG==================")
	p2pdcrm.SendMsgToPeer(enodes,ss)
    }
    
    // 2.8
    // send c_kw to proper node, MtA(k, w)   zk
    var mkw = make(map[string]*big.Int)
    var mkw_mtazk2 = make(map[string]*MtAZK.MtAZK2Proof)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	if IsCurNode(enodes,cur_enode) {
	    u1PaillierPk := GetPaillierPk(save,k)
	    u1Kw1Cipher := u1PaillierPk.HomoMul(ukc[en[0]], w1)
	    v1U1StarCipher, u1VR1,_ := u1PaillierPk.Encrypt(vU1Star[k])
	    u1Kw1Cipher = u1PaillierPk.HomoAdd(u1Kw1Cipher, v1U1StarCipher) // send to u1
	    u1u1MtAZK2Proof2 := MtAZK.MtAZK2Prove(w1, vU1Star[k], u1VR1, ukc[cur_enode], ukc3[cur_enode], zkfactproof[cur_enode])
	    mkw[en[0]] = u1Kw1Cipher
	    mkw_mtazk2[en[0]] = u1u1MtAZK2Proof2
	    continue
	}
	
	u2PaillierPk := GetPaillierPk(save,k)
	u2Kw1Cipher := u2PaillierPk.HomoMul(ukc[en[0]], w1)
	v2U1StarCipher, u2VR1,_ := u2PaillierPk.Encrypt(vU1Star[k])
	u2Kw1Cipher = u2PaillierPk.HomoAdd(u2Kw1Cipher,v2U1StarCipher) // send to u2
	u2u1MtAZK2Proof2 := MtAZK.MtAZK2Prove(w1, vU1Star[k], u2VR1, ukc[en[0]], u2PaillierPk, zkfactproof[cur_enode])

	mp = []string{msgprex,cur_enode}
	enode = strings.Join(mp,"-")
	s0 = "MKW"
	s1 = string(u2Kw1Cipher.Bytes()) 
	//////
	s2 := string(u2u1MtAZK2Proof2.Z.Bytes())
	s3 := string(u2u1MtAZK2Proof2.ZBar.Bytes())
	s4 := string(u2u1MtAZK2Proof2.T.Bytes())
	s5 := string(u2u1MtAZK2Proof2.V.Bytes())
	s6 := string(u2u1MtAZK2Proof2.W.Bytes())
	s7 := string(u2u1MtAZK2Proof2.S.Bytes())
	s8 := string(u2u1MtAZK2Proof2.S1.Bytes())
	s9 := string(u2u1MtAZK2Proof2.S2.Bytes())
	s10 := string(u2u1MtAZK2Proof2.T1.Bytes())
	s11 := string(u2u1MtAZK2Proof2.T2.Bytes())
	///////

	ss = enode + sep + s0 + sep + s1 + sep + s2 + sep + s3 + sep + s4 + sep + s5 + sep + s6 + sep + s7 + sep + s8 + sep + s9 + sep + s10 + sep + s11
	log.Debug("================kg ec2 round four,send msg,code is MKW==================")
	p2pdcrm.SendMsgToPeer(enodes,ss)
    }

    // 2.9
    // receive c_kGamma from proper node, MtA(k, gamma)   zk
     _,cherr = GetChannelValue(ch_t,w.bmkg)
    if cherr != nil {
	log.Debug("get w.bmkg timeout.")
	var ret2 Err
	ret2.info = "get MKG timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    mkgs := make([]string,ThresHold-1)
    for i=0;i<(ThresHold-1);i++ {
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
		
		z := new(big.Int).SetBytes([]byte(mm[3]))
		zbar := new(big.Int).SetBytes([]byte(mm[4]))
		t := new(big.Int).SetBytes([]byte(mm[5]))
		v := new(big.Int).SetBytes([]byte(mm[6]))
		w := new(big.Int).SetBytes([]byte(mm[7]))
		s := new(big.Int).SetBytes([]byte(mm[8]))
		s1 := new(big.Int).SetBytes([]byte(mm[9]))
		s2 := new(big.Int).SetBytes([]byte(mm[10]))
		t1 := new(big.Int).SetBytes([]byte(mm[11]))
		t2 := new(big.Int).SetBytes([]byte(mm[12]))
		mtAZK2Proof := &MtAZK.MtAZK2Proof{Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
		mkg_mtazk2[en[0]] = mtAZK2Proof
		break
	    }
	}
    }

    // 2.10
    // receive c_kw from proper node, MtA(k, w)    zk
    _,cherr = GetChannelValue(ch_t,w.bmkw)
    if cherr != nil {
	log.Debug("get w.bmkw timeout.")
	var ret2 Err
	ret2.info = "get MKW timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    mkws := make([]string,ThresHold-1)
    for i=0;i<(ThresHold-1);i++ {
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

		z := new(big.Int).SetBytes([]byte(mm[3]))
		zbar := new(big.Int).SetBytes([]byte(mm[4]))
		t := new(big.Int).SetBytes([]byte(mm[5]))
		v := new(big.Int).SetBytes([]byte(mm[6]))
		w := new(big.Int).SetBytes([]byte(mm[7]))
		s := new(big.Int).SetBytes([]byte(mm[8]))
		s1 := new(big.Int).SetBytes([]byte(mm[9]))
		s2 := new(big.Int).SetBytes([]byte(mm[10]))
		t1 := new(big.Int).SetBytes([]byte(mm[11]))
		t2 := new(big.Int).SetBytes([]byte(mm[12]))
		mtAZK2Proof := &MtAZK.MtAZK2Proof{Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
		mkw_mtazk2[en[0]] = mtAZK2Proof
		break
	    }
	}
    }
    
    // 2.11 verify zk
    for _,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	rlt111 := mkg_mtazk2[en[0]].MtAZK2Verify(ukc[cur_enode], mkg[en[0]],ukc3[cur_enode], zkfactproof[en[0]])
	if !rlt111 {
	    log.Debug("mkg mtazk2 verify fail.")
	    var ret2 Err
	    ret2.info = "mkg mtazk2 verify fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}

	rlt112 := mkw_mtazk2[en[0]].MtAZK2Verify(ukc[cur_enode], mkw[en[0]], ukc3[cur_enode], zkfactproof[en[0]])
	if !rlt112 {
	    log.Debug("mkw mtazk2 verify fail.")
	    var ret2 Err
	    ret2.info = "mkw mtazk2 verify fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
    }
    
    // 2.12
    // decrypt c_kGamma to get alpha, MtA(k, gamma)
    // MtA(k, gamma)
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
    
    alpha1 := make([]*big.Int,ThresHold)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	alpha1U1, _ := u1PaillierSk.Decrypt(mkg[en[0]])
	alpha1[k] = alpha1U1
    }

    // 2.13
    // decrypt c_kw to get u, MtA(k, w)
    // MtA(k, w)
    uu1 := make([]*big.Int,ThresHold)
    for k,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	u1U1, _ := u1PaillierSk.Decrypt(mkw[en[0]])
	uu1[k] = u1U1
    }

    // 2.14
    // calculate delta, MtA(k, gamma)
    delta1 := alpha1[0]
    for i=0;i<ThresHold;i++ {
	if i == 0 {
	    continue
	}
	delta1 = new(big.Int).Add(delta1,alpha1[i])
    }
    for i=0;i<ThresHold;i++ {
	delta1 = new(big.Int).Add(delta1, betaU1[i])
    }

    // 2.15
    // calculate sigma, MtA(k, w)
    sigma1 := uu1[0]
    for i=0;i<ThresHold;i++ {
	if i == 0 {
	    continue
	}
	sigma1 = new(big.Int).Add(sigma1,uu1[i])
    }
    for i=0;i<ThresHold;i++ {
	sigma1 = new(big.Int).Add(sigma1, vU1[i])
    }

    // 3. Broadcast
    // delta: delta1, delta2, delta3
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

    // 1. Receive Broadcast
    // delta: delta1, delta2, delta3
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

    dels := make([]string,ThresHold-1)
    for i=0;i<(ThresHold-1);i++ {
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
		    del = new(big.Int).Sub(zero,del) //bug:-xxxxxxx
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
    
    // 2. calculate deltaSum
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

    // 3. Broadcast
    // commitU1GammaG.D, commitU2GammaG.D, commitU3GammaG.D
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

    // 1. Receive Broadcast
    // commitU1GammaG.D, commitU2GammaG.D, commitU3GammaG.D
    _,cherr = GetChannelValue(ch_t,w.bd11_1)
    if cherr != nil {
	log.Debug("get w.bd11_1 timeout in sign.")
	var ret2 Err
	ret2.info = "get D11 timeout in sign."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    d11s := make([]string,ThresHold-1)
    for i=0;i<(ThresHold-1);i++ {
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

    c11s := make([]string,ThresHold-1)
    for i=0;i<(ThresHold-1);i++ {
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

    // 2. verify and de-commitment to get GammaG
    
    // for all nodes, construct the commitment by the receiving C and D
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

    log.Debug("===========Sign_ec2,[Signature Generation][Round 4] 2. all nodes verify commit(GammaG):=============")

    // for all nodes, verify the commitment
    for _,id := range idSign {
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

    // for all nodes, de-commitment
    var ug = make(map[string][]*big.Int)
    for _,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	_, u1GammaG := udecom[en[0]].DeCommit()
	ug[en[0]] = u1GammaG
    }

    // for all nodes, calculate the GammaGSum
    var GammaGSumx *big.Int
    var GammaGSumy *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	GammaGSumx = (ug[en[0]])[0]
	GammaGSumy = (ug[en[0]])[1]
	break
    }

    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	GammaGSumx, GammaGSumy = secp256k1.S256().Add(GammaGSumx, GammaGSumy, (ug[en[0]])[0],(ug[en[0]])[1])
    }
    log.Debug("========Sign_ec2,","GammaGSumx",GammaGSumx,"GammaGSumy",GammaGSumy,"","===========")
	
    // 3. calculate deltaSum^-1 * GammaGSum
    deltaSumInverse := new(big.Int).ModInverse(deltaSum, secp256k1.S256().N)
    deltaGammaGx, deltaGammaGy := secp256k1.S256().ScalarMult(GammaGSumx, GammaGSumy, deltaSumInverse.Bytes())

    // 4. get r = deltaGammaGx
    r := deltaGammaGx

    if r.Cmp(zero) == 0 {
	log.Debug("sign error: r equal zero.")
	var ret2 Err
	ret2.info = "sign error: r equal zero."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }
    
    // 5. calculate s
    mMtA,_ := new(big.Int).SetString(message,16)
    
    mk1 := new(big.Int).Mul(mMtA, u1K)
    rSigma1 := new(big.Int).Mul(deltaGammaGx, sigma1)
    us1 := new(big.Int).Add(mk1, rSigma1)
    us1 = new(big.Int).Mod(us1, secp256k1.S256().N)
    log.Debug("=========Sign_ec2,","us1",us1,"","==========")
    
    // 6. calculate S = s * R
    S1x, S1y := secp256k1.S256().ScalarMult(deltaGammaGx, deltaGammaGy, us1.Bytes())
    log.Debug("=========Sign_ec2,","S1x",S1x,"","==========")
    log.Debug("=========Sign_ec2,","S1y",S1y,"","==========")
    
    // 7. Broadcast
    // S: S1, S2, S3
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "S1"
    s1 = string(S1x.Bytes())
    s2 := string(S1y.Bytes())
    ss = enode + sep + s0 + sep + s1 + sep + s2
    log.Debug("================sign ec2 round seven,send msg,code is S1==================")
    SendMsgToDcrmGroup(ss)

    // 1. Receive Broadcast
    // S: S1, S2, S3
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

    us1s := make([]string,ThresHold-1)
    for i=0;i<(ThresHold-1);i++ {
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

    // 2. calculate SAll
    var SAllx *big.Int
    var SAlly *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	SAllx = (s1s[en[0]])[0]
	SAlly = (s1s[en[0]])[1]
	break
    }

    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	SAllx, SAlly = secp256k1.S256().Add(SAllx, SAlly, (s1s[en[0]])[0],(s1s[en[0]])[1])
    }
    log.Debug("[Signature Generation][Test] verify SAll ?= m*G + r*PK:")
    log.Debug("========Sign_ec2,","SAllx",SAllx,"SAlly",SAlly,"","===========")
	
    // 3. verify SAll ?= m*G + r*PK
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

    // 4. Broadcast
    // s: s1, s2, s3
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "SS1"
    s1 = string(us1.Bytes())
    ss = enode + sep + s0 + sep + s1
    log.Debug("================sign ec2 round eight,send msg,code is SS1==================")
    SendMsgToDcrmGroup(ss)

    // 1. Receive Broadcast
    // s: s1, s2, s3
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

    uss1s := make([]string,ThresHold-1)
    for i=0;i<(ThresHold-1);i++ {
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

    // 2. calculate s
    var sSum *big.Int
    for _,id := range idSign {
	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	sSum = ss1s[en[0]]
	break
    }

    for k,id := range idSign {
	if k == 0 {
	    continue
	}

	enodes := GetEnodesByUid(id)
	en := strings.Split(string(enodes[8:]),"@")
	sSum = new(big.Int).Add(sSum,ss1s[en[0]])
    }
    sSum = new(big.Int).Mod(sSum, secp256k1.S256().N) 
   
    // 3. justify the s
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
    
    // **[Test]  verify signature with MtA
    // ** verify the signature
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
    // **[End-Test]  verify signature with MtA

    signature := new(ECDSASignature)
    signature.New()
    signature.SetR(r)
    signature.SetS(s)

    //v
    recid := secp256k1.Get_ecdsa_sign_v(computeRxMtA,computeRyMtA)
    if tokenType == "ETH" && bb {
	recid ^=1
    }
    if tokenType == "BTC" && bb {
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

func GetZkFactProof(save string,index int) *paillier.ZkFactProof {
    if save == "" || index < 0 {
	return nil
    }

    mm := strings.Split(save, sep11)
    s := 4 + 4*NodeCnt + 5*index////????? TODO
    h1 := new(big.Int).SetBytes([]byte(mm[s]))
    h2 := new(big.Int).SetBytes([]byte(mm[s+1]))
    y := new(big.Int).SetBytes([]byte(mm[s+2]))
    e := new(big.Int).SetBytes([]byte(mm[s+3]))
    n := new(big.Int).SetBytes([]byte(mm[s+4]))
    zkFactProof := &paillier.ZkFactProof{H1: h1, H2: h2, Y: y, E: e,N: n}
    return zkFactProof
}

