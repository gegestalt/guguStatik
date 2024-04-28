#include <unordered_map>
#include <vector>
#include <iostream>
using namespace std;

class Solution {
public:
    int findLucky(vector<int>& arr) {
        std::unordered_map<int, int> freq;

        for (int num : arr) {
            ++freq[num];
        }

        int result = -1;
        for (auto p : freq) {
            if (p.first == p.second)
                result = std::max(result, p.first);
        }

        return result;
    }   
};

int main() {
    vector<int> arr = {2, 2, 3, 4, 5, 5, 5, 6, 0, 7, 6, 3, 6, 6, 1, 13, 6}; 
    int luckyNumber = Solution().findLucky(arr);
    cout << "Lucky number: " << luckyNumber << endl;  // Print the result (optional)
    return 0;
}
