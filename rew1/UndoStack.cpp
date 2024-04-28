#include "UndoStack.h"
using namespace std;

//push operation of UndoStack class
void UndoStack::push(char operation, string employee_name, string project_name, int project_priority) {
    StackNode* newNode = new StackNode(operation, employee_name, project_name, project_priority);
    newNode->next = top;
    top = newNode;
}

// Pop an operation from the stack
void UndoStack::pop(char& operation, string& employee_name, string& project_name, int& project_priority) {
    
    StackNode* temp = top;
    operation = temp->operation;
    employee_name = temp->employee_name;
    project_name = temp->project_name;
    project_priority = temp->project_priority;
    top = top->next;
    delete temp;
}

// Check if the stack is empty
bool UndoStack::isEmpty() {
    return top == nullptr;
}

// Clear the stack
void UndoStack::clear() {
    while (!isEmpty()) {
        StackNode* temp = top;
        top = top->next;
        delete temp;
    }
}