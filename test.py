import requests

jane_pubkey = "02ba30c90c39b3033cfa6faf365e62c237f616cafc2e715fcf0882eab7eafb0899"
jane_lnd_host = "localhost:8080"
jane_macaroon_hex = "0201036C6E6402F801030A100264464797012C20D0967BD33AA38B641201301A160A0761646472657373120472656164120577726974651A130A04696E666F120472656164120577726974651A170A08696E766F69636573120472656164120577726974651A210A086D616361726F6F6E120867656E6572617465120472656164120577726974651A160A076D657373616765120472656164120577726974651A170A086F6666636861696E120472656164120577726974651A160A076F6E636861696E120472656164120577726974651A140A057065657273120472656164120577726974651A180A067369676E6572120867656E65726174651204726561640000062076DA970074009894D708930E2035926E84DA67B976D0AB15FA19155B8B723B50"

bob_pubkey = "03a61b9354d054a8f4ba594e9e88a7b4a768bcfbf7d31b998fe9962be43e57c7ba"
bob_lnd_host = "localhost:8081"
bob_macaroon_hex = "0201036C6E6402F801030A102C0C3D10FC3397BAABA37D7C96F6CF381201301A160A0761646472657373120472656164120577726974651A130A04696E666F120472656164120577726974651A170A08696E766F69636573120472656164120577726974651A210A086D616361726F6F6E120867656E6572617465120472656164120577726974651A160A076D657373616765120472656164120577726974651A170A086F6666636861696E120472656164120577726974651A160A076F6E636861696E120472656164120577726974651A140A057065657273120472656164120577726974651A180A067369676E6572120867656E657261746512047265616400000620FB023040D95442761A99F09D4B39E2E4346B5960F8D8B8F3ADFFD1F49FE17717"


def test():

    """
    bob create invoice
    bob has a channel with routing node
    jane has a channel with routing node with minimal liquidity
    jane call LSPD endpoint
    jane pays the pay req
    """





test()