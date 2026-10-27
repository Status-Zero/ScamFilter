namespace ScamFilter
{
    /*
     * A vector (a list of numbers) that stores only its nonzero entries.
     *
     * Each message's text vector has one slot per vocabulary entry, maybe 60,000 slots, but a
     * single message only uses a few hundred of them. The rest are 0. So instead of a
     * 60,000-long double[], we keep two short parallel arrays:
     *
     *     Indices = { 12,   407,  9031 }     which slots are nonzero
     *     Values  = { 0.21, 0.55, 0.13 }     what's in them
     *
     * This saves about 99% of the memory, and it makes the dot product (the core of the model)
     * cost a few hundred multiplications instead of 60,000, because multiplying by 0 is skipped.
     */
    public class SparseVector
    {
        public readonly int[] Indices;     // which slots have a value (in no particular order)
        public readonly double[] Values;   // the value in each of those slots

        public SparseVector(int[] indices, double[] values)
        {
            Indices = indices;
            Values = values;
        }

        // Number of nonzero entries (not the full length of the vector).
        public int Size
        {
            get { return Indices.Length; }
        }

        /*
         * Dot product with a regular array:  x . w = x_0*w_0 + x_1*w_1 + ...
         * Only the nonzero x_j are visited, since every other term would be 0.
         */
        public double Dot(double[] dense)
        {
            double sum = 0.0;
            for (int k = 0; k < Indices.Length; k++)
            {
                sum += Values[k] * dense[Indices[k]];
            }
            return sum;
        }
    }
}
