using System.Collections.Generic;

namespace ScamFilter
{
    /*
     * A random number generator that produces EXACTLY the same numbers as Java's
     * java.util.Random for the same seed.
     *
     * Why not C#'s own Random? Same seed, different algorithm, different numbers. Shuffles and
     * splits would come out differently, so results couldn't be compared against the original
     * Java version. With this, both versions split and shuffle identically, which is how the
     * port was checked for correctness.
     *
     * How it works: a "linear congruential generator", one of the oldest random number tricks.
     * It keeps a 48-bit number called the seed, and each step does
     *
     *     seed = (seed * 0x5DEECE66D + 0xB) mod 2^48
     *
     * then hands out the top bits. The sequence looks random but is completely determined by
     * the starting seed, which is exactly what "same seed = same results every run" needs.
     * (Fine for shuffling; never use something like this for passwords or security.)
     */
    public class JavaRandom
    {
        private const long Multiplier = 0x5DEECE66DL;
        private const long Addend = 0xBL;
        private const long Mask = (1L << 48) - 1;   // keeps only the low 48 bits

        private long seed;

        public JavaRandom(long seed)
        {
            this.seed = (seed ^ Multiplier) & Mask;   // Java scrambles the starting seed this way
        }

        // The core step: advance the seed and return its top `bits` bits.
        private int Next(int bits)
        {
            seed = (seed * Multiplier + Addend) & Mask;
            return (int) (seed >> (48 - bits));
        }

        // A random int from 0 up to (but not including) bound. Same algorithm as Java's nextInt(bound).
        public int NextInt(int bound)
        {
            if ((bound & -bound) == bound)
            {
                // bound is a power of 2: just take the top bits
                return (int) ((bound * (long) Next(31)) >> 31);
            }
            int bits;
            int val;
            do
            {
                // Reject values from the incomplete last "block" so every result is equally likely.
                bits = Next(31);
                val = bits % bound;
            }
            while (bits - val + (bound - 1) < 0);   // relies on int overflow, exactly like Java
            return val;
        }

        // A random double from 0.0 up to (but not including) 1.0, built from 53 random bits.
        public double NextDouble()
        {
            return (((long) Next(26) << 27) + Next(27)) * (1.0 / (1L << 53));
        }

        // A random true or false, like Java's Random.nextBoolean().
        public bool NextBoolean()
        {
            return Next(1) != 0;
        }

        /*
         * Shuffles a list exactly like Java's Collections.shuffle(list, random): the Fisher-Yates
         * shuffle. Walk backwards, swapping each slot with a random slot at or before it.
         * Every ordering is equally likely.
         */
        public void Shuffle<T>(List<T> list)
        {
            for (int i = list.Count; i > 1; i--)
            {
                int j = NextInt(i);
                T tmp = list[i - 1];
                list[i - 1] = list[j];
                list[j] = tmp;
            }
        }

        // The same shuffle, for an int array.
        public void Shuffle(int[] array)
        {
            for (int i = array.Length - 1; i > 0; i--)
            {
                int j = NextInt(i + 1);
                int tmp = array[i];
                array[i] = array[j];
                array[j] = tmp;
            }
        }
    }
}
