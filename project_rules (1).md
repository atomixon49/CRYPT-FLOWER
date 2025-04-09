# Project Rules

## Development Rules
1. **Code Quality**
   - All code must be well-commented
   - Follow consistent naming conventions
   - Use meaningful variable and function names
   - Keep functions small and focused on a single task
   - Implement proper error handling

2. **Security Rules**
   - Never hardcode cryptographic keys
   - Use secure random number generators
   - Implement proper key management
   - Follow the principle of least privilege
   - Validate all inputs
   - Sanitize all outputs

3. **Testing Rules**
   - Write tests before implementing features (TDD approach)
   - Maintain at least 90% test coverage
   - Test both positive and negative scenarios
   - Include edge cases in tests
   - Document test procedures and results

4. **Documentation Rules**
   - Document all functions and classes
   - Keep documentation up-to-date with code changes
   - Include examples in documentation
   - Document security considerations
   - Create user-friendly documentation

## Error Handling Rules
1. **Error Documentation**
   - Document all errors in the errors.md file
   - Include the error message, cause, and solution
   - Categorize errors (e.g., implementation, design, security)
   - Track recurring errors to identify patterns

2. **Error Resolution**
   - Address critical security errors immediately
   - Prioritize errors based on impact
   - Update rules based on lessons learned from errors
   - Implement fixes systematically

## Workflow Rules
1. **Task Management**
   - Update task_tracker.md after completing each task
   - Break complex tasks into smaller subtasks
   - Focus on one task at a time
   - Document dependencies between tasks
   - When editing task_tracker.md:
     - Verify the entire file structure before saving changes
     - Check for duplicate tasks or sections
     - Ensure proper indentation and formatting
     - Use the view command to verify the current state before making changes
     - Make incremental changes and verify after each change

2. **Version Control**
   - Make small, focused commits
   - Write clear commit messages
   - Create branches for major features
   - Review code before merging

3. **Progress Tracking**
   - Update progress daily
   - Document roadblocks and solutions
   - Track time spent on each task
   - Regularly review and adjust timelines

## Security Testing Rules
1. **Cryptanalysis**
   - Test against known attack vectors
   - Implement formal security proofs where possible
   - Conduct differential cryptanalysis
   - Test against side-channel attacks

2. **Implementation Testing**
   - Verify correct implementation of algorithms
   - Test with standard test vectors
   - Validate against reference implementations
   - Check for timing attacks and other side-channel vulnerabilities
