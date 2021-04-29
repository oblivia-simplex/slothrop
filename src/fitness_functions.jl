EAX = Hatchery.Unicorn.X86.Register.EAX
EBX = Hatchery.Unicorn.X86.Register.EBX

REGISTERS = Hatchery.Unicorn.Register[EAX, EBX]

Register = Hatchery.Unicorn.Register

function hatch!(g, registers::Vector{Register}=REGISTERS)
  if g.phenotype ≡ nothing
    g.phenotype = Hatchery.evaluate(g.chromosome, registers)
  end
  @assert g.phenotype !== nothing
end


function has_regs(g, registers...)
  all(r in keys(g.phenotype.regs) for r in registers)
end

###-----------------------------------------------------------###

function ret_count(g)
  hatch!(g)
  g.fitness = [g.phenotype.ret_count]
end

function max_eax(g)
  hatch!(g, [EAX])
  if EAX in keys(g.phenotype.regs)
    g.fitness = [g.phenotype.regs[EAX] / 0xFFFF_FFFF]
  else
    g.fitness = [0.0]
  end
end

function max_ones(g)
  registers = [EAX, EBX]
  hatch!(g, registers)
  if has_regs(g, EAX, EBX)
    ones = count_ones(g.phenotype.regs[EAX] & g.phenotype.regs[EBX])
    g.fitness = [ones / 32.0]
  else
    g.fitness = [0.0]
  end
end

