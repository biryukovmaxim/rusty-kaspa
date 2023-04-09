let kaspa = require('./kaspa/kaspa_wasm');
kaspa.init_console_panic_hook();

const {
    Header, Uint256, Uint192, State, Hash
} = kaspa;

(async ()=>{
   let header = new Header(
        0,//version
        [[new Hash("0000000000000000000000000000000000000000000000000000000000000000")]],//parents_by_level_array
        new Hash("0000000000000000000000000000000000000000000000000000000000000000"),//hash_merkle_root
        new Hash("0000000000000000000000000000000000000000000000000000000000000000"),//accepted_id_merkle_root
        new Hash("0000000000000000000000000000000000000000000000000000000000000000"),//utxo_commitment
        0n,//timestamp
        0,//bits
        0n,//nonce
        0n,//daa_score
        new Uint192(0n),//blue_work
        0n,//blue_score
        new Hash("0000000000000000000000000000000000000000000000000000000000000000")//pruning_point
    );

    let state = new State(header);

    let [a, v] = state.checkPow(0n);

    console.log("state", a, v, v.toBigInt())

})();

