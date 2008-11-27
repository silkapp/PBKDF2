{- | Implementation of Password Based Key Derivation Function, from RSA labs. 

See TK (rsa link) 

and TK (haskell cafe discussion)
-}
module Crypto.PBKDF2 (pbkdf2, pbkdf2') where

import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as L
import GHC.Word
import Control.Monad (foldM)
import Random
import Data.Digest.SHA512 (hash)
import Data.Word 
import Data.Bits
import Data.Binary

newtype Password = Password [Word8]
newtype Salt = Salt [Word8]
newtype HashedPass = HashedPass [Word8]
  deriving Show


t = pbkdf2 ( Password . toWord8s $ "meh" ) ( Salt . toWord8s $ "moo" )

{- | A reasonable default for rsa pbkdf2. 

> pbkdf2 = pbkdf2' (prfSHA512,64) 1000 64

SHA512 outputs 64 bytes. At least 1000 iters is suggested by PKCS#5 (rsa link above). I chose 5000 because this takes my computer a little over a second to compute a simple key derivation (see t test function in source)

Dklen of 64 seemed reasonable to me: if this is being stored in a database, doesn't take too much space.

Computational barriers can be raised by increasing number of iters
-} 
--sha512 generates 64-element octet lists, so set hlen to 64. 
-- not sure if this is correct. does hlen refer to length in bytes or bits?
pbkdf2 :: Password -> Salt -> HashedPass
pbkdf2 = pbkdf2' (prfSHA512,64) 5000 64


{- | Password Based Key Derivation Function, from RSA labs.

> pbkdf2' (prf,hlen) cIters dklen (Password pass) (Salt salt) 

prf: pseudo random function

hlen: length of prf output

cIters: Number of iterations of prf

dklen: Length of the derived key (hashed password)
-}
pbkdf2' :: ( ([Word8] -> [Word8] -> [Word8]),Integer) -> Integer -> Integer -> Password -> Salt -> HashedPass
pbkdf2' (prf,hlen) cIters dklen (Password pass) (Salt salt) 
  | dklen > ( (2^32-1) * hlen) = error $ "pbkdf2, (dklen,hlen) : " ++ (show (dklen,hlen))
  | otherwise = 
    let --l,r :: Int
        l = ceiling $ (fromIntegral dklen) / (fromIntegral hlen )
        r = dklen - ( (l-1) * hlen)
        ustream :: [Word8] -> [Word8] -> [[Word8]]
        ustream p s = let x = prf p s
                      in  x : ustream p x    
        --us :: Integer -> [[Word8]]
        us i = take (fromIntegral cIters) $ ustream pass ( salt `myor` ((intToFourWord8s i) ))
        --f :: [Word8] -> [Word8] -> Integer -> Integer -> [Word8]
        f pass salt cIters i = foldr1 myxor $ us i
        ts :: [[Word8]]
        ts = map (f pass salt cIters) ( [1..l] )
    in HashedPass . take (fromIntegral dklen) . concat $ ts

-- The spec says
-- Here, INT (i) is a four-octet encoding of the integer i, most significant octet first.
-- I'm reading from the right... is this the right thing?
toWord8s x = L.unpack . encode $ x

--intToFourWord8s :: Integer -> [Word8]
intToFourWord8s i = let w8s =  toWord8s $ i
                    in drop (length w8s -4) w8s

myxor :: [Word8] -> [Word8] -> [Word8]
myxor = zipWith xor 

myor :: [Word8] -> [Word8] -> [Word8]
myor = zipWith (.|.)

{- > prfSHA512 hlen seed pass ...

hlen is the length of the pseudo random output. (not really, fix me)

output is always 64 bytes long
-}
prfSHA512 :: [Word8] -> [Word8] -> [Word8]
prfSHA512 seed pass = hash $ seed ++ pass

t2 = prfSHA512 (toWord8s "asdf") (toWord8s "jkl; asdfjl; asjdfnkl;ajsdfl;jk;sn")
