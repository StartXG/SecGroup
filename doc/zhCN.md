# 安全组管理器

该项目是一个用于阿里云ECS的安全组管理器。它允许您管理安全组规则，包括创建、删除和查询规则。

## 构建环境

- Go 1.23.3
- Fyne v2.5.4
- GORM v1.25.12
- SQLite v1.5.7
- 阿里云SDK

## 使用方法

1. 克隆仓库：
    ```sh
    git clone https://github.com/yourusername/SecGroupV2.git
    cd SecGroupV2
    ```

2. 安装依赖：
    ```sh
    go mod tidy
    ```

3. 运行应用程序：
    ```sh
    go run main.go
    ```

4. 应用程序将打开一个GUI，您可以在其中管理您的安全组规则。