#include <string>
using namespace std;
struct StackNode {
    char operation;
    string employee_name;
    string project_name;
    int project_priority;
    StackNode* next;

    StackNode(char operation, string employee_name, string project_name, int project_priority)
        : operation(operation), employee_name(employee_name), project_name(project_name), project_priority(project_priority), next(nullptr) {}
};

class UndoStack {
private:
    StackNode* top;
public:
    UndoStack() : top(nullptr) {}
    void push(char operation, string employee_name, string project_name, int project_priority);
    void pop(char& operation, string& employee_name, string& project_name, int& project_priority);
    bool isEmpty();
    void clear();
};