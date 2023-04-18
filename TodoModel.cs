namespace TodoApi;

public class TodoModel
{
    public int Id { get; set; }
    public string? Name { get; set; }

    public bool? IsCompleted { get; set; }
}