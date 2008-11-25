{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.PBKDF2 (pbkdf2) where

import qualified Data.ByteString as B
import GHC.Word
import Control.Monad (foldM)
import Random
import Data.Digest.SHA512 (hash)
import Data.Word 
import Data.Bits

pbkdf2 :: ([Word8] -> [Word8] -> [Word8]) -> Int -> [Word8] -> [Word8] -> Int -> Int -> [Word8] 
pbkdf2 prf hlen pass salt cIters dklen 
  | dklen > ( (2^32-1) * hlen) = error $ "pbkdf2, dklen : " ++ (show dklen)
  | otherwise = 
    let --l,r :: Int
        l = ceiling $ (fromIntegral dklen) / (fromIntegral hlen )
        r = dklen - ( (l-1) * hlen)
        ustream :: [Word8] -> [Word8] -> [[Word8]]
        ustream p s = let x = prf p s
                      in  x : ustream p x    
        us :: Int -> [[Word8]]
        us i = take cIters $ ustream pass ( salt `myor` (fourOctetEnc (intToFourWord8s i) ))
        f :: [Word8] -> [Word8] -> Int -> Int -> [Word8]
        f pass salt cIters i = foldr1 myxor $ us i
        ts :: [[Word8]]
        ts = map (f pass salt cIters) ( [1..l] )
    in take dklen . concat $ ts

intToFourWord8s :: Int -> [Word8]
intToFourWord8s = undefined

-- fix later
-- what is this supposed to do?
fourOctetEnc = id

myxor :: [Word8] -> [Word8] -> [Word8]
myxor = zipWith xor 

myor :: [Word8] -> [Word8] -> [Word8]
myor = zipWith (.|.)
prf :: [Word8] -> [Word8] -> IO [Word8]
prf pass k = return . hash $ pass ++ k
